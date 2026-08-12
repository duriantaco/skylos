"""Shared payload for a taint scanner that could not finish a file.

A scanner that raises must not leave the file looking clean. Each ``scan()``
records this finding instead of only printing to stderr, so the failure reaches
``analysis_errors`` and the run fails closed.
"""

import sys


RULE_ID = "SKY-ANALYSIS-INCOMPLETE"


def scanner_failure_finding(file_path, scanner: str, error: BaseException) -> dict:
    message = " ".join(str(error).splitlines())[:500] or type(error).__name__
    return {
        "rule_id": RULE_ID,
        "severity": "HIGH",
        "kind": "processing_error",
        "error_type": type(error).__name__,
        "scanner": scanner,
        "message": f"{scanner} analysis did not complete: {message}",
        "file": str(file_path),
        "line": 1,
        "column": 1,
        # Kept in step with _analysis_error_payload; reports render "Python ?"
        # without it. Sharing that builder would mean importing the analyzer.
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
    }
