import time
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from .context import ContextBuilder
from .agents import AgentConfig, create_agent
from .validator import ResultValidator, deduplicate_findings, merge_findings
from .ui import SkylosUI, estimate_cost

from .schemas import Confidence, AnalysisResult
from skylos.config import load_config
from skylos.llm.graph import CodeGraph
from skylos.file_discovery import discover_source_files


def _norm_path(path) -> str:
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


class AnalyzerConfig:
    def __init__(
        self,
        model="gpt-4.1",
        api_key=None,
        provider=None,
        base_url=None,
        temperature=0.0,
        max_tokens=4096,
        enable_security=True,
        enable_quality=True,
        strict_validation=False,
        min_confidence=Confidence.LOW,
        quiet=False,
        json_output=False,
        stream=True,
        parallel=False,
        max_workers=1,
        max_chunk_tokens=1000,
        smart_filter=True,
        complexity_threshold=5,
        batch_functions=True,
        batch_size=10,
        full_file_review=False,
        repo_context_map=None,
        force_full_file_paths=None,
    ):
        self.model = model
        self.api_key = api_key
        self.provider = provider
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens

        self.enable_security = enable_security
        self.enable_quality = enable_quality

        self.strict_validation = strict_validation
        self.min_confidence = min_confidence

        self.quiet = quiet
        self.json_output = json_output
        self.stream = stream

        self.parallel = parallel
        self.max_workers = max_workers
        self.max_chunk_tokens = max_chunk_tokens

        self.smart_filter = smart_filter
        self.complexity_threshold = complexity_threshold
        self.batch_functions = batch_functions
        self.batch_size = batch_size
        self.full_file_review = full_file_review
        self.repo_context_map = repo_context_map or {}
        self.force_full_file_paths = {
            _norm_path(path) for path in (force_full_file_paths or set())
        }


class SkylosLLM:
    def __init__(self, config=None):
        self.config = config or AnalyzerConfig()

        self.ui = SkylosUI(quiet=self.config.quiet)
        self.context_builder = ContextBuilder(
            max_context_tokens=self.config.max_chunk_tokens * 2
        )

        self.validator = ResultValidator(
            strict=self.config.strict_validation,
            min_confidence=self.config.min_confidence,
        )

        self.agent_config = AgentConfig()
        self.agent_config.model = self.config.model
        self.agent_config.api_key = self.config.api_key
        self.agent_config.provider = self.config.provider
        self.agent_config.base_url = self.config.base_url
        self.agent_config.temperature = self.config.temperature
        self.agent_config.max_tokens = self.config.max_tokens
        self.agent_config.stream = self.config.stream

        self._agents = {}

    def _reset_usage_counters(self):
        for agent in self._agents.values():
            adapter = getattr(agent, "_adapter", None)
            if adapter and hasattr(adapter, "reset_usage"):
                adapter.reset_usage()

    def _total_tokens_used(self):
        total = 0
        for agent in self._agents.values():
            adapter = getattr(agent, "_adapter", None)
            if not adapter:
                continue
            usage = getattr(adapter, "total_usage", None) or {}
            total += int(usage.get("total_tokens") or 0)
        return total

    def _get_agent(self, agent_type):
        if agent_type not in self._agents:
            self._agents[agent_type] = create_agent(agent_type, self.agent_config)
        return self._agents[agent_type]

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

    def _should_analyze_security_function(self, func_name, def_data, graph):
        taint_paths = graph.find_taint_paths(func_name)
        if taint_paths:
            return True

        node = def_data.get("node")
        if node:
            complexity = self._estimate_complexity(node)
            if complexity >= self.config.complexity_threshold:
                return True

        sensitive = [
            "auth",
            "login",
            "password",
            "token",
            "secret",
            "sql",
            "query",
            "execute",
            "eval",
            "exec",
            "shell",
            "command",
            "system",
            "pickle",
            "yaml",
            "upload",
            "file",
            "path",
        ]
        func_lower = func_name.lower()
        for pattern in sensitive:
            if pattern in func_lower:
                return True

        return False

    def _should_analyze_quality_function(self, func_name, def_data):
        node = def_data.get("node")
        if node is None:
            return False

        complexity = self._estimate_complexity(node)
        if complexity >= self.config.complexity_threshold:
            return True

        if self._function_length(node) >= 12:
            return True

        if self._function_parameter_count(node) >= 4:
            return True

        if self._return_site_count(node) >= 2:
            return True

        if self._control_flow_count(node) >= 3:
            return True

        if self._has_exception_handling(node):
            return True

        func_lower = func_name.lower()
        quality_signals = (
            "build",
            "format",
            "normalize",
            "parse",
            "render",
            "resolve",
            "validate",
        )
        return any(token in func_lower for token in quality_signals)

    def _active_review_modes(self, issue_types=None):
        if not issue_types:
            modes = set()
            if self.config.enable_security:
                modes.add("security")
            if self.config.enable_quality:
                modes.add("quality")
            return modes

        modes = set()
        for issue_type in issue_types:
            name = str(issue_type).lower().strip()
            if name in {"security", "security_audit"}:
                modes.add("security")
            if name == "quality":
                modes.add("quality")
        return modes

    def _should_analyze_function(
        self, func_name, def_data, graph, *, issue_types=None, total_functions=0
    ):
        if not self.config.smart_filter:
            return True

        modes = self._active_review_modes(issue_types)
        if not modes:
            return True

        if "quality" in modes and total_functions and total_functions <= 3:
            return True

        return (
            "security" in modes
            and self._should_analyze_security_function(func_name, def_data, graph)
        ) or (
            "quality" in modes
            and self._should_analyze_quality_function(func_name, def_data)
        )

    def _build_batched_context(self, functions_data, graph, file_path, defs_map=None):
        return self._build_batched_context_for_modes(
            functions_data,
            graph,
            file_path,
            defs_map=defs_map,
            issue_types=None,
        )

    def _build_batched_context_for_modes(
        self, functions_data, graph, file_path, defs_map=None, issue_types=None
    ):
        parts = [f"# File: {file_path}\n"]
        modes = self._active_review_modes(issue_types)
        include_security_hints = "security" in modes
        include_quality_hints = "quality" in modes

        for i, (func_name, def_data, taint_paths) in enumerate(functions_data):
            context = graph.get_review_context(
                func_name,
                defs_map=defs_map,
                include_security_hints=include_security_hints,
                include_quality_hints=include_quality_hints,
            )
            if context:
                parts.append(f"## Function {i + 1}: {func_name}")
                if taint_paths:
                    parts.append(f"# WARNING: {len(taint_paths)} taint flow(s)")
                parts.append(context)
                parts.append("")

        return "\n".join(parts)

    def _analyze_whole_file(
        self,
        source,
        file_path,
        defs_map=None,
        chunk_start_line=1,
        issue_types=None,
        **kwargs,
    ):
        normalized_issue_types = {
            str(t).lower().strip() for t in (issue_types or []) if str(t).strip()
        }

        type_to_agent = {
            "security": "security",
            "quality": "quality",
            "security_audit": "security_audit",
        }

        if not issue_types:
            wants_security = self.config.enable_security
            wants_quality = self.config.enable_quality
            if wants_security and wants_quality:
                agent_types = ["review"]
            else:
                agent_types = []
                if wants_security:
                    agent_types.append("security")
                if wants_quality:
                    agent_types.append("quality")

            if not agent_types:
                agent_types = ["security_audit"]
        else:
            # Fail fast if caller asks for dead_code through per-file analysis
            for t in issue_types:
                if str(t).lower().strip() == "dead_code":
                    raise ValueError(
                        "Dead code analysis is not a per-file operation. "
                        "Use DeadCodeAgent.verify_candidates() with static "
                        "candidates instead (pipeline Phase 2a)."
                    )

            if {"security", "quality"} <= normalized_issue_types:
                agent_types = ["review"]
            else:
                agent_types = []
                for t in issue_types:
                    a = type_to_agent.get(str(t).lower().strip())
                    if a:
                        agent_types.append(a)

            if not agent_types:
                agent_types = ["security_audit"]

        include_review_hints = any(
            agent_type in {"review", "quality"} for agent_type in agent_types
        )
        repo_metadata = self.config.repo_context_map.get(_norm_path(file_path))
        try:
            context = self.context_builder.build_analysis_context(
                source,
                file_path=file_path,
                defs_map=defs_map,
                include_review_hints=include_review_hints,
                repo_metadata=repo_metadata,
            )
        except TypeError:
            context = self.context_builder.build_analysis_context(
                source,
                file_path=file_path,
                defs_map=defs_map,
                include_review_hints=include_review_hints,
            )

        all_findings = []

        for agent_type in agent_types:
            agent = self._get_agent(agent_type)

            try:
                if not self.config.quiet:
                    with self.ui.status(f"Analyzing {Path(file_path).name}..."):
                        findings = agent.analyze(
                            source, file_path, defs_map, context=context
                        )
                else:
                    findings = agent.analyze(
                        source, file_path, defs_map, context=context
                    )

            except Exception as e:
                self.ui.print(f"Error analyzing {file_path}: {e}", style="red")
                continue

            if chunk_start_line != 1:
                for f in findings:
                    f.location.line += chunk_start_line - 1

            all_findings.extend(findings)

        return all_findings

    def analyze_file(
        self,
        file_path,
        defs_map=None,
        static_findings=None,
        issue_types=None,
    ):
        file_path = Path(file_path)

        if not file_path.exists():
            return []

        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.ui.print(f"Error reading {file_path}: {e}", style="red")
            return []

        all_findings = []
        file_norm = _norm_path(file_path)
        force_full_file_review = file_norm in self.config.force_full_file_paths

        if self.config.full_file_review or force_full_file_review:
            all_findings = self._analyze_whole_file(
                source,
                str(file_path),
                defs_map,
                issue_types=issue_types,
            )
        else:
            graph = CodeGraph()
            graph.build(source)

            if graph.definitions:
                functions_to_analyze = []
                skipped = 0
                function_def_count = sum(
                    1
                    for def_data in graph.definitions.values()
                    if def_data["type"] in ("function", "method")
                )
                modes = self._active_review_modes(issue_types)

                for func_name, def_data in graph.definitions.items():
                    if def_data["type"] not in ("function", "method"):
                        continue

                    if self._should_analyze_function(
                        func_name,
                        def_data,
                        graph,
                        issue_types=issue_types,
                        total_functions=function_def_count,
                    ):
                        taint_paths = graph.find_taint_paths(func_name)
                        functions_to_analyze.append((func_name, def_data, taint_paths))
                    else:
                        skipped += 1

                if not self.config.quiet and skipped > 0:
                    total = len(functions_to_analyze) + skipped
                    self.ui.print(
                        f"  Analyzing {len(functions_to_analyze)}/{total} functions (skipped {skipped} low-risk)",
                        style="dim",
                    )

                if functions_to_analyze:
                    if self.config.batch_functions and len(functions_to_analyze) > 1:
                        for i in range(
                            0, len(functions_to_analyze), self.config.batch_size
                        ):
                            batch = functions_to_analyze[i : i + self.config.batch_size]
                            batch_context = self._build_batched_context_for_modes(
                                batch,
                                graph,
                                file_path,
                                defs_map,
                                issue_types=issue_types,
                            )

                            findings = self._analyze_whole_file(
                                batch_context,
                                str(file_path),
                                defs_map,
                                issue_types=issue_types,
                            )

                            for finding in findings:
                                for func_name, def_data, taint_paths in batch:
                                    if func_name.split(".")[-1] in str(finding.message):
                                        finding.location.line = (
                                            def_data["start"] + finding.location.line
                                        )
                                        if taint_paths:
                                            for tp in taint_paths:
                                                if (
                                                    tp["sink_type"]
                                                    in finding.message.lower()
                                                ):
                                                    finding.confidence = Confidence.HIGH
                                        break

                            all_findings.extend(findings)
                    else:
                        for func_name, def_data, taint_paths in functions_to_analyze:
                            context = graph.get_review_context(
                                func_name,
                                defs_map=defs_map,
                                include_security_hints="security" in modes,
                                include_quality_hints="quality" in modes,
                            )
                            if not context:
                                continue

                            findings = self._analyze_whole_file(
                                context,
                                str(file_path),
                                defs_map,
                                issue_types=issue_types,
                            )

                            if taint_paths:
                                for f in findings:
                                    for tp in taint_paths:
                                        if tp["sink_type"] in f.message.lower():
                                            f.confidence = Confidence.HIGH

                            start_line = def_data["start"] + 1
                            for f in findings:
                                f.location.line = start_line + f.location.line - 1

                            all_findings.extend(findings)
                elif "quality" in modes:
                    all_findings = self._analyze_whole_file(
                        source,
                        str(file_path),
                        defs_map,
                        issue_types=issue_types,
                    )
            else:
                all_findings = self._analyze_whole_file(
                    source, str(file_path), defs_map, issue_types=issue_types
                )

        validated, _ = self.validator.validate(all_findings, source, str(file_path))

        if static_findings:
            validated = merge_findings(validated, static_findings, str(file_path))

        validated = deduplicate_findings(validated)

        return validated

    def _count_lines(self, file_path):
        try:
            return len(Path(file_path).read_text(encoding="utf-8").splitlines())
        except Exception:
            return 0

    def _generate_summary(self, result):
        if not result.findings:
            return "No issues found"

        by_severity = {}
        for f in result.findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                parts.append(f"{by_severity[sev]} {sev}")

        return f"Found {len(result.findings)} issues: " + ", ".join(parts)

    def analyze_files(
        self,
        files,
        defs_map=None,
        static_findings=None,
        progress_callback=None,
        issue_types=None,
    ):
        start_time = time.time()
        all_findings = []
        total_lines = 0
        self._reset_usage_counters()

        files = [Path(f) for f in files]

        if not self.config.quiet:
            self.ui.print_banner()
            tokens, cost = estimate_cost(files, self.config.model)
            self.ui.print(
                f"{len(files)} files, ~{tokens:,} tokens, ~${cost:.4f}", style="dim"
            )

        if self.config.parallel and len(files) > 1:
            with self.ui.create_progress() as progress:
                task = progress.add_task("Analyzing...", total=len(files))

                with ThreadPoolExecutor(
                    max_workers=self.config.max_workers
                ) as executor:
                    future_to_file = {
                        executor.submit(
                            self.analyze_file,
                            f,
                            defs_map,
                            static_findings.get(str(f)) if static_findings else None,
                            issue_types,
                        ): f
                        for f in files
                    }

                    for i, future in enumerate(as_completed(future_to_file)):
                        file = future_to_file[future]
                        try:
                            findings = future.result()
                            all_findings.extend(findings)
                            total_lines += self._count_lines(file)
                        except Exception as e:
                            self.ui.print(f"{file.name}: {e}", style="red")

                        progress.update(
                            task,
                            advance=1,
                            description=f"[{i + 1}/{len(files)}] {file.name}",
                        )
                        if progress_callback:
                            progress_callback(i + 1, len(files), file)
        else:
            with self.ui.create_progress() as progress:
                task = progress.add_task("Analyzing...", total=len(files))

                for i, file in enumerate(files):
                    progress.update(
                        task, description=f"[{i + 1}/{len(files)}] {file.name}"
                    )

                    findings = self.analyze_file(
                        file,
                        defs_map,
                        static_findings.get(str(file)) if static_findings else None,
                        issue_types=issue_types,
                    )
                    all_findings.extend(findings)
                    total_lines += self._count_lines(file)

                    progress.update(task, advance=1)
                    if progress_callback:
                        progress_callback(i + 1, len(files), file)

        elapsed_ms = int((time.time() - start_time) * 1000)

        result = AnalysisResult(
            findings=all_findings,
            files_analyzed=len(files),
            total_lines=total_lines,
            analysis_time_ms=elapsed_ms,
            model_used=self.config.model,
            tokens_used=self._total_tokens_used(),
        )
        result.summary = self._generate_summary(result)

        return result

    def analyze_project(
        self,
        project_path,
        exclude_folders=None,
        defs_map=None,
        static_findings=None,
        issue_types=None,
    ):
        project_path = Path(project_path)

        if not project_path.exists():
            return AnalysisResult(summary="Project path not found")

        exclude = set(load_config(project_path).get("exclude", []))
        exclude.update(exclude_folders or [])
        exclude.update(
            {
                "__pycache__",
                ".git",
                ".venv",
                "venv",
                "node_modules",
                ".pytest_cache",
                ".mypy_cache",
                "build",
                "dist",
                ".tox",
                ".eggs",
                "*.egg-info",
            }
        )

        files = discover_source_files(
            project_path,
            [".py"],
            exclude_folders=exclude,
        )

        if not files:
            return AnalysisResult(summary="No Python files found")

        return self.analyze_files(
            files, defs_map, static_findings, issue_types=issue_types
        )

    def fix_issue(self, file_path, issue_line, issue_message, defs_map=None):
        file_path = Path(file_path)
        if not file_path.exists():
            return None

        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception:
            return None

        context = self.context_builder.build_fix_context(
            source, str(file_path), issue_line, issue_message, defs_map
        )

        fixer = self._get_agent("fixer")
        return fixer.fix(
            source, str(file_path), issue_line, issue_message, defs_map, context
        )

    def print_results(self, result, format="table", output_file=None):
        if format == "json":
            output = json.dumps(result.to_dict(), indent=2)
            if output_file:
                Path(output_file).write_text(output)
            elif not self.config.quiet:
                print(output)
            return

        if format == "sarif":
            output = json.dumps(result.to_sarif(), indent=2)
            if output_file:
                Path(output_file).write_text(output)
            elif not self.config.quiet:
                print(output)
            return

        if self.config.quiet:
            return

        if format == "tree":
            self.ui.print_findings_tree(result.findings)
        else:
            self.ui.print_findings_table(result.findings)

        self.ui.print_summary(result)


def analyze(path, model="gpt-4.1", issue_types=None, **kwargs):
    config = AnalyzerConfig(model=model, **kwargs)
    analyzer = SkylosLLM(config)

    path = Path(path)
    if path.is_file():
        findings = analyzer.analyze_file(path, issue_types=issue_types)
        return AnalysisResult(findings=findings, files_analyzed=1)
    else:
        return analyzer.analyze_project(path, issue_types=issue_types)


def audit(path, model="gpt-4.1", **kwargs):
    return analyze(path, model=model, issue_types=["security_audit"], **kwargs)


def fix(file_path, line, message, model="gpt-4.1"):
    config = AnalyzerConfig(model=model)
    analyzer = SkylosLLM(config)
    return analyzer.fix_issue(file_path, line, message)
