import time
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from .context import ContextBuilder
from .agents import AgentConfig, create_agent
from .validator import ResultValidator, deduplicate_findings, merge_findings
from .ui import SkylosUI, estimate_cost

from .schemas import Severity, Confidence, AnalysisResult


class AnalyzerConfig:
    def __init__(
        self,
        model="gpt-4.1",
        api_key=None,
        temperature=0.1,
        max_tokens=4096,
        enable_security=True,
        enable_dead_code=True,
        enable_quality=True,
        strict_validation=False,
        min_confidence=Confidence.LOW,
        quiet=False,
        json_output=False,
        stream=True,
        parallel=False,
        max_workers=1,
        max_chunk_tokens=2000,
    ):
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens

        self.enable_security = enable_security
        self.enable_dead_code = enable_dead_code
        self.enable_quality = enable_quality

        self.strict_validation = strict_validation
        self.min_confidence = min_confidence

        self.quiet = quiet
        self.json_output = json_output
        self.stream = stream

        self.parallel = parallel
        self.max_workers = max_workers
        self.max_chunk_tokens = max_chunk_tokens


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
        self.agent_config.temperature = self.config.temperature
        self.agent_config.max_tokens = self.config.max_tokens
        self.agent_config.stream = self.config.stream

        self._agents = {}

    def _analyze_whole_file(
        self,
        source,
        file_path,
        defs_map=None,
        chunk_start_line=1,
        issue_types=None,
        **kwargs,
    ):
        context = self.context_builder.build_analysis_context(
            source, file_path=file_path, defs_map=defs_map
        )

        type_to_agent = {
            "security": "security",
            "dead_code": "dead_code",
            "quality": "quality",
            "security_audit": "security_audit",
        }

        if not issue_types:
            agent_types = []
            if self.config.enable_security:
                agent_types.append("security")
            if self.config.enable_dead_code:
                agent_types.append("dead_code")
            if self.config.enable_quality:
                agent_types.append("quality")

            if not agent_types:
                agent_types = ["security_audit"]
        else:
            agent_types = []
            for t in issue_types:
                a = type_to_agent.get(str(t).lower().strip())
                if a:
                    agent_types.append(a)

            if not agent_types:
                agent_types = ["security_audit"]

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

    def _chunk_by_size(self, source, _, max_chars):
        lines = source.splitlines(True)
        chunks = []
        buf = []
        buf_len = 0
        start_line = 1
        line_no = 1

        last_blank_cut = None

        for line in lines:
            buf.append(line)
            buf_len += len(line)

            if line.strip() == "":
                last_blank_cut = (len(buf), buf_len, line_no)

            if buf_len >= max_chars:
                if last_blank_cut:
                    cut_idx, _, cut_line = last_blank_cut
                    content = "".join(buf[:cut_idx])
                    chunks.append({"start_line": start_line, "content": content})

                    leftover = buf[cut_idx:]
                    buf = leftover
                    buf_len = sum(len(x) for x in buf)
                    start_line = cut_line + 1
                    last_blank_cut = None
                else:
                    content = "".join(buf)
                    chunks.append({"start_line": start_line, "content": content})
                    buf = []
                    buf_len = 0
                    start_line = line_no + 1
                    last_blank_cut = None

            line_no += 1

        if buf:
            chunks.append({"start_line": start_line, "content": "".join(buf)})

        return chunks

    def _get_agent(self, agent_type):
        if agent_type not in self._agents:
            self._agents[agent_type] = create_agent(agent_type, self.agent_config)
        return self._agents[agent_type]

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

        chars_per_token = 4
        max_chars = self.config.max_chunk_tokens * chars_per_token

        if len(source) <= max_chars:
            all_findings = self._analyze_whole_file(
                source,
                str(file_path),
                defs_map,
                issue_types=issue_types,
            )
        else:
            chunks = self._chunk_by_size(source, str(file_path), max_chars)
            all_findings = []
            for chunk in chunks:
                all_findings.extend(
                    self._analyze_whole_file(
                        chunk["content"],
                        str(file_path),
                        defs_map,
                        chunk_start_line=chunk["start_line"],
                        issue_types=issue_types,
                    )
                )

        validated, _ = self.validator.validate(all_findings, source, str(file_path))

        if static_findings:
            validated = merge_findings(validated, static_findings, str(file_path))

        validated = deduplicate_findings(validated)

        return validated

    def _analyze_chunk(
        self,
        chunk,
        defs_map=None,
    ):
        context = self.context_builder.build_analysis_context(
            chunk, file_path=chunk.file_path, defs_map=defs_map
        )

        agent = self._get_agent("security_audit")

        try:
            if not self.config.quiet:
                with self.ui.status(f"Analyzing {chunk.name}..."):
                    findings = agent.analyze(
                        chunk.content,
                        chunk.file_path,
                        defs_map,
                        context=context,
                    )
            else:
                findings = agent.analyze(
                    chunk.content,
                    chunk.file_path,
                    defs_map,
                    context=context,
                )
        except Exception as e:
            self.ui.print(f"Error analyzing {chunk.name}: {e}", style="red")
            return []

        if chunk.start_line != 1:
            for finding in findings:
                finding.location.line += chunk.start_line - 1

        return findings

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

        result = []
        for f in files:
            result.append(Path(f))
        files = result

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

        exclude = set(exclude_folders or [])
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
            }
        )

        files = []
        for f in project_path.rglob("*.py"):
            skip = False
            for part in f.parts:
                if part in exclude or part.endswith(".egg-info"):
                    skip = True
                    break
            if not skip:
                files.append(f)

        if not files:
            return AnalysisResult(summary="No Python files found")

        return self.analyze_files(
            files, defs_map, static_findings, issue_types=issue_types
        )

    def fix_issue(
        self,
        file_path,
        line,
        message,
        defs_map=None,
    ):
        file_path = Path(file_path)

        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception:
            return None

        context = self.context_builder.build_fix_context(
            source, str(file_path), line, message, defs_map
        )

        fixer = self._get_agent("fixer")

        if not self.config.quiet:
            with self.ui.status(f"Generating fix for {file_path.name}:{line}..."):
                fix = fixer.fix(
                    source, str(file_path), line, message, defs_map, context=context
                )
        else:
            fix = fixer.fix(
                source, str(file_path), line, message, defs_map, context=context
            )

        return fix

    def _severity_order(self):
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }

    def _extract_enclosing_symbol(self, source, issue_line):
        lines = source.splitlines()
        current_line_index = min(max(issue_line - 1, 0), len(lines) - 1)

        while current_line_index >= 0:
            line_content = lines[current_line_index].lstrip()

            is_function = line_content.startswith("def ")
            is_class = line_content.startswith("class ")

            if is_function or is_class:
                without_params = line_content.split("(", 1)[0]
                without_colon = without_params.split(":", 1)[0]
                symbol_name = (
                    without_colon.replace("def ", "").replace("class ", "").strip()
                )

                if symbol_name:
                    return symbol_name

            current_line_index -= 1

        return None

    def _validate_fixed_code_for_apply(self, original_source, fixed_source, issue_line):
        if not fixed_source.strip():
            return False, "Empty fixed code"

        try:
            import ast

            ast.parse(fixed_source)
        except Exception as e:
            return False, f"Fixed code does not parse: {e}"

        orig_lines = max(1, len(original_source.splitlines()))
        fixed_lines = len(fixed_source.splitlines())

        if fixed_lines < int(orig_lines * 0.50):
            return False, "Fixed file is too short vs original (likely snippet)"
        if fixed_lines > int(orig_lines * 2.00):
            return False, "Fixed file is too large vs original (suspicious expansion)"

        sym = self._extract_enclosing_symbol(original_source, issue_line)
        if sym and sym not in fixed_source:
            return False, f"Enclosing symbol '{sym}' disappeared from fixed file"

        return True, ""

    def _apply_fix_to_disk(self, file_path, fixed_source):
        from pathlib import Path

        Path(file_path).write_text(fixed_source, encoding="utf-8")

    def fix_all(self, findings, defs_map=None, max_fixes=None, apply=False):
        fixes = []

        if not findings:
            return fixes

        self.ui.console.print(
            "\n[brand]Generating fix proposals (critical first)...[/brand]"
        )

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }

        def sort_key(f):
            severity = severity_order.get(f.severity, 99)
            file_path = str(f.location.file)
            line_num = f.location.line or 0
            return (severity, file_path, line_num)

        sorted_findings = sorted(findings, key=sort_key)

        total_done = 0

        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]:
            findings_for_severity = []
            for f in sorted_findings:
                if f.severity == severity:
                    findings_for_severity.append(f)

            if not findings_for_severity:
                continue

            if severity != Severity.CRITICAL:
                if not self.ui.confirm(
                    f"Proceed to {severity.value} issues?", default=False
                ):
                    break

            for finding in findings_for_severity:
                if max_fixes and total_done >= max_fixes:
                    return fixes

                fix = self.fix_issue(
                    file_path=finding.location.file,
                    line=finding.location.line,
                    message=finding.message,
                    defs_map=defs_map,
                )

                if not fix:
                    if not self.ui.confirm(
                        "No fix generated. Continue to next?", default=True
                    ):
                        return fixes
                    continue

                fixes.append(fix)
                total_done += 1
                self.ui.print_fix(fix)

                if apply:
                    if self.ui.confirm("Apply this fix to the file?", default=False):
                        try:
                            file_path = Path(finding.location.file)
                            original_source = file_path.read_text(encoding="utf-8")

                            is_valid, reason = self._validate_fixed_code_for_apply(
                                original_source, fix.fixed_code, finding.location.line
                            )

                            if not is_valid:
                                self.ui.console.print(
                                    f"[yellow]Refusing to apply:[/yellow] {reason}"
                                )
                            else:
                                file_path.write_text(fix.fixed_code, encoding="utf-8")
                                self.ui.console.print(
                                    f"[green]Applied fix to {file_path}[/green]"
                                )
                        except Exception as e:
                            self.ui.console.print(f"[red]Failed to apply: {e}[/red]")

                if not self.ui.confirm("Continue to next issue?", default=True):
                    return fixes

        return fixes

    def _count_lines(self, file):
        try:
            return len(file.read_text(encoding="utf-8").splitlines())
        except Exception:
            return 0

    def _generate_summary(self, result):
        if not result.findings:
            return "No issues found!"

        counts = {}
        for f in result.findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1

        parts = []
        for sev in ["critical", "high", "medium", "low"]:
            if sev in counts:
                parts.append(f"{counts[sev]} {sev}")

        return f"Found {len(result.findings)} issues: " + ", ".join(parts)

    def print_results(
        self,
        result,
        format="table",
        output_file=None,
    ):
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


def fix(
    file_path,
    line,
    message,
    model="gpt-4.1",
):
    config = AnalyzerConfig(model=model)
    analyzer = SkylosLLM(config)
    return analyzer.fix_issue(file_path, line, message)
