from __future__ import annotations

from .schemas import CodeLocation, Confidence, Finding, IssueType, Severity


class AgentReviewStaticFindingMixin:
    def _estimate_complexity(self, node):
        import ast

        complexity = 1
        for child in ast.walk(node):
            if isinstance(
                child,
                (
                    ast.If,
                    ast.While,
                    ast.For,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.comprehension,
                ),
            ):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def _function_length(self, node):
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if start is None:
            return 0
        if end is None:
            end = start
        return max(end - start + 1, 0)

    def _function_parameter_count(self, node):
        if node is None:
            return 0

        args = getattr(node, "args", None)
        if args is None:
            return 0

        count = 0
        for arg in getattr(args, "posonlyargs", []) or []:
            if getattr(arg, "arg", None) not in ("self", "cls"):
                count += 1
        for arg in getattr(args, "args", []) or []:
            if getattr(arg, "arg", None) not in ("self", "cls"):
                count += 1
        count += len(getattr(args, "kwonlyargs", []) or [])
        return count

    def _return_site_count(self, node):
        import ast

        if node is None:
            return 0
        return sum(1 for child in ast.walk(node) if isinstance(child, ast.Return))

    def _control_flow_count(self, node):
        import ast

        if node is None:
            return 0
        return sum(
            1
            for child in ast.walk(node)
            if isinstance(
                child,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.With,
                    ast.Match,
                ),
            )
        )

    def _has_exception_handling(self, node):
        import ast

        if node is None:
            return False
        return any(
            isinstance(child, (ast.Try, ast.TryStar)) for child in ast.walk(node)
        )

    def _collect_static_agent_findings(self, source, file_path, issue_types=None):
        import ast

        modes = self._active_review_modes(issue_types)
        if not modes:
            return []

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if "quality" in modes:
                findings.extend(self._static_async_blocking_findings(node, file_path))
                quality = self._static_structural_quality_finding(node, file_path)
                if quality is not None:
                    findings.append(quality)
            if "security" in modes:
                upload = self._static_upload_traversal_finding(node, file_path)
                if upload is not None:
                    findings.append(upload)
                archive = self._static_archive_extraction_finding(node, file_path)
                if archive is not None:
                    findings.append(archive)

        return findings

    def _static_structural_quality_finding(self, node, file_path):
        complexity = self._estimate_complexity(node)
        control_flow = self._control_flow_count(node)
        params = self._function_parameter_count(node)
        returns = self._return_site_count(node)
        length = self._function_length(node)
        has_exception = self._has_exception_handling(node)

        branch_hotspot = control_flow >= 3 and returns >= 3
        debt_hotspot = (
            params >= 5 and control_flow >= 4 and returns >= 3 and has_exception
        )
        if not branch_hotspot and not debt_hotspot and complexity < 7:
            return None

        if debt_hotspot:
            message = f"Technical debt hotspot in '{node.name}'."
            explanation = (
                f"Static analysis found a wide, branch-heavy function '{node.name}' "
                f"with {params} parameters, {control_flow} control-flow nodes, "
                f"{returns} returns, and exception handling."
            )
            severity = Severity.HIGH
        else:
            message = f"Branch-heavy control flow in '{node.name}'."
            explanation = (
                f"Static analysis found branch-heavy control flow in '{node.name}': "
                f"complexity={complexity}, control_flow={control_flow}, "
                f"returns={returns}, length={length}."
            )
            severity = Severity.MEDIUM

        return Finding(
            rule_id="SKY-Q301",
            issue_type=IssueType.QUALITY,
            severity=severity,
            confidence=Confidence.HIGH,
            message=message,
            location=CodeLocation(file=str(file_path), line=node.lineno),
            explanation=explanation,
            suggestion=(
                "Split the branch-heavy paths into smaller named helpers and keep "
                "the top-level function focused on orchestration."
            ),
            symbol=node.name,
            metadata={
                "source": "static_agent_hint",
                "route_complete": True,
                "route_reason": "deterministic_structural_quality_metrics",
                "route_mode": "quality",
                "complexity": complexity,
                "control_flow": control_flow,
                "returns": returns,
                "params": params,
                "has_exception_handling": has_exception,
            },
        )

    def _static_async_blocking_findings(self, node, file_path):
        import ast

        if not isinstance(node, ast.AsyncFunctionDef):
            return []

        calls = self._async_blocking_calls(node)
        if not calls:
            return []

        call_name, line = calls[0]
        all_calls = ", ".join(name for name, _ in calls[:3])
        return [
            Finding(
                rule_id="SKY-Q401",
                issue_type=IssueType.PERFORMANCE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message=(
                    f"Blocking call '{call_name}' inside async function "
                    f"'{node.name}'."
                ),
                location=CodeLocation(file=str(file_path), line=line),
                explanation=(
                    "Static analysis found blocking synchronous call(s) inside "
                    f"async function '{node.name}': {all_calls}."
                ),
                suggestion=(
                    "Use async-native alternatives such as asyncio.sleep(), "
                    "httpx.AsyncClient, aiohttp, or asyncio subprocess APIs."
                ),
                symbol=node.name,
                metadata={
                    "source": "static_agent_hint",
                    "route_complete": True,
                    "route_reason": "blocking_call_inside_async_function",
                    "route_mode": "quality",
                    "blocking_calls": [name for name, _ in calls],
                },
            )
        ]

    def _static_upload_traversal_finding(self, node, file_path):
        if self._function_has_archive_extraction_call(node):
            return None

        upload_vars, unsafe_filename_vars = self._upload_filename_state(node)
        if not unsafe_filename_vars:
            return None

        sink_line = self._upload_traversal_sink_line(
            node, unsafe_filename_vars, upload_vars
        )
        if not sink_line:
            return None

        return Finding(
            rule_id="SKY-D215",
            issue_type=IssueType.SECURITY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message="Path traversal risk in file upload handler.",
            location=CodeLocation(file=str(file_path), line=sink_line),
            explanation=(
                "Static analysis found a request upload filename joined into a "
                "server-side path without basename, resolve, or allowlist validation."
            ),
            suggestion=(
                "Normalize the uploaded filename with basename/secure_filename and "
                "validate the resolved target stays under the upload root."
            ),
            symbol=node.name,
            metadata={
                "source": "static_agent_hint",
                "route_complete": True,
                "route_reason": "upload_filename_reaches_path_sink",
                "route_mode": "security",
                "unsafe_filename_vars": sorted(unsafe_filename_vars),
                "upload_vars": sorted(upload_vars),
            },
            security_details={
                "attack_path": "attacker controls upload filename used in server path",
                "impact": "path traversal or arbitrary file overwrite",
                "fix": "sanitize filename and validate resolved path under upload root",
                "evidence_lines": [sink_line],
                "unsafe_if": "uploaded filename is not normalized and root-checked",
            },
        )

    def _upload_filename_state(self, node):
        import ast

        upload_vars = set()
        unsafe_filename_vars = set()

        for child in ast.walk(node):
            if not isinstance(child, ast.Assign):
                continue

            targets = [target for target in child.targets if isinstance(target, ast.Name)]
            if not targets:
                continue

            if self._is_request_files_expr(child.value):
                upload_vars.update(target.id for target in targets)
            elif not self._is_sanitized_filename_expr(child.value):
                if self._uses_upload_filename(child.value, upload_vars):
                    unsafe_filename_vars.update(target.id for target in targets)

        return upload_vars, unsafe_filename_vars

    def _upload_traversal_sink_line(
        self, node, unsafe_filename_vars, upload_vars
    ):
        import ast

        for child in ast.walk(node):
            if self._unsafe_path_join_line(child, unsafe_filename_vars, upload_vars):
                return child.lineno
            if self._unsafe_open_call_line(child, unsafe_filename_vars, upload_vars):
                return child.lineno
        return 0

    def _unsafe_path_join_line(self, node, unsafe_filename_vars, upload_vars):
        import ast

        return (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Div)
            and self._uses_unsafe_upload_filename(
                node.right, unsafe_filename_vars, upload_vars
            )
        )

    def _unsafe_open_call_line(self, node, unsafe_filename_vars, upload_vars):
        import ast

        return (
            isinstance(node, ast.Call)
            and self._call_name(node.func) == "open"
            and bool(node.args)
            and self._uses_unsafe_upload_filename(
                node.args[0], unsafe_filename_vars, upload_vars
            )
        )

    def _static_archive_extraction_finding(self, node, file_path):
        import ast

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if self._call_name(child.func).split(".")[-1] != "extractall":
                continue
            if any(keyword.arg == "members" for keyword in child.keywords):
                continue
            return Finding(
                rule_id="SKY-D326",
                issue_type=IssueType.SECURITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message="Unsafe archive extraction without member path validation.",
                location=CodeLocation(file=str(file_path), line=child.lineno),
                explanation=(
                    "Static analysis found extractall() without a validated members "
                    "list or extraction-root check."
                ),
                suggestion=(
                    "Validate every archive member path against the extraction root "
                    "before extraction, then pass only validated members."
                ),
                symbol=node.name,
                metadata={
                    "source": "static_agent_hint",
                    "route_complete": True,
                    "route_reason": "archive_extractall_without_members_validation",
                    "route_mode": "security",
                },
                security_details={
                    "attack_path": "attacker-controlled archive member paths",
                    "impact": "zip slip / tar slip file write outside extraction root",
                    "fix": "validate members before extractall",
                    "evidence_lines": [child.lineno],
                    "unsafe_if": "archive members are not root-checked before extraction",
                },
            )

        return None

    def _function_has_archive_extraction_call(self, node):
        import ast

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if self._call_name(child.func).split(".")[-1] in {"extract", "extractall"}:
                return True
        return False

    def _async_blocking_calls(self, node):
        import ast

        calls = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._call_name(child.func)
            if self._is_blocking_call_name(name):
                calls.append((name, child.lineno))
        return calls

    def _has_async_blocking_call(self, node):
        import ast

        if node is None or not isinstance(node, ast.AsyncFunctionDef):
            return False

        return bool(self._async_blocking_calls(node))

    def _is_blocking_call_name(self, name):
        if not name:
            return False

        blocking_roots = {
            "requests",
            "urllib",
            "subprocess",
            "socket",
            "os",
        }
        blocking_names = {
            "open",
        }

        if name == "time.sleep":
            return True
        if name in blocking_names:
            return True
        if name.split(".", 1)[0] in blocking_roots:
            return True

        return False

    def _call_name(self, node):
        import ast

        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._call_name(node.value)
            if base:
                return base + "." + node.attr
            return node.attr
        return ""

    def _is_request_files_expr(self, node):
        import ast

        if isinstance(node, ast.Subscript):
            return self._call_name(node.value) == "request.files"
        if isinstance(node, ast.Call):
            return self._call_name(node.func) == "request.files.get"
        return False

    def _is_sanitized_filename_expr(self, node):
        import ast

        if not isinstance(node, ast.Call):
            return False
        name = self._call_name(node.func)
        return name in {
            "os.path.basename",
            "posixpath.basename",
            "ntpath.basename",
            "secure_filename",
            "werkzeug.utils.secure_filename",
        }

    def _uses_upload_filename(self, node, upload_vars):
        import ast

        if isinstance(node, ast.Attribute) and node.attr == "filename":
            return isinstance(node.value, ast.Name) and node.value.id in upload_vars
        if self._is_request_files_expr(node):
            return True
        if self._is_sanitized_filename_expr(node):
            return False
        return any(
            self._uses_upload_filename(child, upload_vars)
            for child in ast.iter_child_nodes(node)
        )

    def _uses_unsafe_upload_filename(self, node, unsafe_filename_vars, upload_vars):
        import ast

        if isinstance(node, ast.Name):
            return node.id in unsafe_filename_vars
        if self._uses_upload_filename(node, upload_vars):
            return True
        if self._is_sanitized_filename_expr(node):
            return False
        return any(
            self._uses_unsafe_upload_filename(
                child, unsafe_filename_vars, upload_vars
            )
            for child in ast.iter_child_nodes(node)
        )

