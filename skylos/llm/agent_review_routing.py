from __future__ import annotations

from .agent_review_refuters import AgentReviewRefuterMixin
from .agent_review_static import AgentReviewStaticFindingMixin
from .schemas import Confidence, IssueType
from .validator import deduplicate_findings, merge_findings


SECURITY_AUDIT_ISSUE = "security_audit"


class AgentReviewRoutingMixin(
    AgentReviewStaticFindingMixin,
    AgentReviewRefuterMixin,
):
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

        if self._has_async_blocking_call(node):
            return True

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
            if name in {"security", SECURITY_AUDIT_ISSUE}:
                modes.add("security")
            if name == "quality":
                modes.add("quality")
        return modes

    @staticmethod
    def _normalized_issue_types(issue_types=None):
        return {str(t).lower().strip() for t in (issue_types or []) if str(t).strip()}

    def _agent_route(self):
        route = str(getattr(self.config, "agent_route", "full") or "full").strip()
        return route if route in {"full", "static_first", "static_only"} else "full"

    def _static_route_mode_for_finding(self, finding):
        metadata = getattr(finding, "metadata", None) or {}
        route_mode = str(metadata.get("route_mode") or "").strip()
        if route_mode in {"security", "quality"}:
            return route_mode
        if finding.issue_type == IssueType.SECURITY:
            return "security"
        if finding.issue_type in {
            IssueType.QUALITY,
            IssueType.BUG,
            IssueType.PERFORMANCE,
            IssueType.STYLE,
            IssueType.HALLUCINATION,
        }:
            return "quality"
        return ""

    def _static_route_active_modes(self, issue_types=None):
        modes = self._active_review_modes(issue_types)
        if modes:
            return modes
        return set()

    def _is_route_complete_static_finding(self, finding):
        metadata = getattr(finding, "metadata", None) or {}
        if metadata.get("source") != "static_agent_hint":
            return False
        if metadata.get("route_complete") is not True:
            return False
        if not metadata.get("route_reason"):
            return False
        if getattr(finding, "confidence", None) != Confidence.HIGH:
            return False
        if not getattr(finding, "symbol", None):
            return False
        return finding.rule_id in {
            "SKY-D215",
            "SKY-D326",
            "SKY-Q301",
            "SKY-Q401",
        }

    @staticmethod
    def _is_static_agent_hint(finding):
        metadata = getattr(finding, "metadata", None) or {}
        return metadata.get("source") == "static_agent_hint"

    @staticmethod
    def _finding_line_set(finding):
        lines = set()
        line = getattr(getattr(finding, "location", None), "line", None)
        if isinstance(line, int) and line > 0:
            lines.add(line)

        security_details = getattr(finding, "security_details", None) or {}
        for evidence_line in security_details.get("evidence_lines") or []:
            if isinstance(evidence_line, int) and evidence_line > 0:
                lines.add(evidence_line)

        return lines

    @staticmethod
    def _static_finding_line(static_finding):
        if not isinstance(static_finding, dict):
            return 0
        if "line" in static_finding:
            return static_finding.get("line", 0) or 0
        return static_finding.get("lineno", 0) or 0

    @staticmethod
    def _static_finding_rule(static_finding):
        if not isinstance(static_finding, dict):
            return ""
        return static_finding.get("rule_id") or static_finding.get("code") or ""

    @staticmethod
    def _lines_overlap(first_lines, second_lines, *, tolerance=2):
        return any(
            abs(first - second) <= tolerance
            for first in first_lines
            for second in second_lines
        )

    def _findings_overlap_static_hint(self, hint, other):
        if getattr(hint, "rule_id", None) != getattr(other, "rule_id", None):
            return False

        hint_symbol = getattr(hint, "symbol", None)
        other_symbol = getattr(other, "symbol", None)
        if hint_symbol and other_symbol and hint_symbol == other_symbol:
            return True

        return self._lines_overlap(
            self._finding_line_set(hint),
            self._finding_line_set(other),
        )

    def _static_finding_overlaps_hint(self, hint, static_finding):
        if getattr(hint, "rule_id", None) != self._static_finding_rule(static_finding):
            return False

        static_line = self._static_finding_line(static_finding)
        if not isinstance(static_line, int) or static_line <= 0:
            return False

        return self._lines_overlap(self._finding_line_set(hint), {static_line})

    def _drop_duplicate_static_agent_hints(self, findings, static_findings=None):
        non_hint_findings = [
            finding
            for finding in findings
            if not self._is_static_agent_hint(finding)
        ]
        static_findings = static_findings or []
        unique = []

        for finding in findings:
            if not self._is_static_agent_hint(finding):
                unique.append(finding)
                continue

            if any(
                self._findings_overlap_static_hint(finding, other)
                for other in non_hint_findings
            ):
                continue

            if any(
                self._static_finding_overlaps_hint(finding, static_finding)
                for static_finding in static_findings
            ):
                continue

            unique.append(finding)

        return unique

    def _static_route_complete(self, static_agent_findings, issue_types=None):
        if self._agent_route() != "static_first":
            return False
        if not static_agent_findings:
            return False
        if not all(
            self._is_route_complete_static_finding(finding)
            for finding in static_agent_findings
        ):
            return False

        active_modes = self._static_route_active_modes(issue_types)
        finding_modes = {
            self._static_route_mode_for_finding(finding)
            for finding in static_agent_findings
        }
        finding_modes.discard("")

        return len(active_modes) == 1 and finding_modes == active_modes

    def _should_use_static_only_route(self):
        return self._agent_route() == "static_only"

    def _finalize_file_findings(
        self,
        findings,
        source,
        file_path,
        static_findings=None,
        issue_types=None,
    ):
        validated, _ = self.validator.validate(findings, source, str(file_path))
        validated = self._remap_handler_symbols(validated, source)
        validated = self._filter_refuted_agent_findings(
            validated, source, issue_types=issue_types
        )
        validated = self._drop_duplicate_static_agent_hints(
            validated, static_findings=static_findings
        )

        if static_findings:
            validated = merge_findings(validated, static_findings, str(file_path))

        return deduplicate_findings(validated)

    def _should_use_whole_file_review(self, file_norm, issue_types=None):
        if (
            self.config.full_file_review
            or file_norm in self.config.force_full_file_paths
        ):
            return True
        return SECURITY_AUDIT_ISSUE in self._normalized_issue_types(issue_types)

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
