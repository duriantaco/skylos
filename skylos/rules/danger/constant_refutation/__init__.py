"""Constant-argument refutation of Python danger findings.

A deterministic post-pass over the scan's danger findings. It runs sparse
conditional constant propagation (dead-branch pruning, constant-key
containers, closed-world interprocedural constants) over the repository and
refutes a finding only when it proves that the claimed dangerous operand is a
constant or otherwise safe under Skylos's own sink model, for example SQL
built only from literal fragments and an ``int()``-cast limit, or a shell
command chosen by a branch that can never run. Unknown, unsupported and
failing cases keep the finding.

A refuted finding is not listed. It is recorded in ``suppressed`` with the
reason ``"constant-argument refutation: <proof tag>"`` and the engine's
certificate under ``"refutation"``, so it stays auditable.

Scope limits (each can only keep more findings):

* Findings Skylos already marks ``low_risk_context: constant-argument`` or
  ``constant-shell-command`` are left alone: Skylos keeps those raw, hides
  them from the default list and still counts them in the gate.
* SKY-D326 (unsafe archive extraction) is never refuted: a constant archive
  path says nothing about the archive's members, which carry the attack.
* PyYAML loader-identity proofs (``S2b-pyyaml``) are not used: Skylos only
  reports ``yaml.load(..., Loader=yaml.SafeLoader)`` when its own, stricter
  tamper proof could not finish (for example a dynamic plugin import).
* A file with more than 50 findings in scope is left alone, so the cost
  stays bounded (each finding re-interprets its enclosing scope).
* Nothing is refuted in a project whose Python code inspects frames
  (``f_locals``, ``sys._getframe``, ``inspect.currentframe`` ...): since
  Python 3.13 (PEP 667) a frame's ``f_locals`` writes through to the
  function's local variables, which the engine assumes it sees completely.

Opt out with ``SKYLOS_CONSTANT_REFUTATION=0`` (also ``false``, ``no``, ``off``).
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

ENV_VAR = "SKYLOS_CONSTANT_REFUTATION"
REASON_PREFIX = "constant-argument refutation"
_DISABLE_VALUES = {"0", "false", "no", "off"}
_EXCLUDED_RULES = {"SKY-D326"}
_EXCLUDED_MECHANISMS = {"S2b-pyyaml"}
_MAX_CANDIDATES_PER_FILE = 50
_FRAME_ACCESS = re.compile(
    r"\b(?:f_locals|f_back|f_trace|tb_frame|gi_frame|cr_frame|ag_frame|_getframe"
    r"|currentframe|getouterframes|getinnerframes|settrace|setprofile|LocalsToFast)\b"
    r"|\binspect\s*\.\s*(?:stack|trace)\b"
)


def refutation_enabled(environ=None) -> bool:
    env = os.environ if environ is None else environ
    return str(env.get(ENV_VAR, "1")).strip().lower() not in _DISABLE_VALUES


def _in_scope(finding, rules, skylos_constant_reasons) -> bool:
    if not isinstance(finding, dict) or finding.get("rule_id") not in rules:
        return False
    if not str(finding.get("file") or "").endswith(".py"):
        return False
    low_risk = finding.get("low_risk_context")
    reason = low_risk.get("reason") if isinstance(low_risk, dict) else None
    return reason not in skylos_constant_reasons


def _project_inspects_frames(project) -> bool:
    for rel in project.py_files():
        try:
            text = (project.root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return True
        if _FRAME_ACCESS.search(text):
            return True
    return False


def _json_safe(value):
    try:
        return json.loads(json.dumps(value, sort_keys=True))
    except (TypeError, ValueError):
        return repr(value)


def refute_constant_argument_findings(findings, *, project_root, suppressed):
    """Findings without the ones the engine refutes; refuted ones go to ``suppressed``.

    Fails closed: when disabled, when nothing is in scope, when the project
    inspects frames, or on any engine error, the findings are returned
    unchanged.
    """
    if not findings or not refutation_enabled():
        return findings
    try:
        from skylos.rules.danger.constant_refutation import engine as E

        rules = (
            E.F0_RULES | E.S1_RULES | E.S1_INTRA_ONLY | {"SKY-D206", "SKY-D216"} | set(E.PROV_KEYS)
        ) - _EXCLUDED_RULES
        candidates = [f for f in findings if _in_scope(f, rules, E.F0_REASONS)]
        per_file = {}
        for f in candidates:
            per_file[str(f.get("file"))] = per_file.get(str(f.get("file")), 0) + 1
        candidates = [f for f in candidates if per_file[str(f.get("file"))] <= _MAX_CANDIDATES_PER_FILE]
        if not candidates:
            return findings
        root = Path(project_root)
        if _project_inspects_frames(E.Project(root, E.Config())):
            return findings
        kept, log = E.refute(candidates, root)
    except Exception:
        logger.debug("constant-argument refutation failed", exc_info=True)
        return findings

    kept_ids = {id(f) for f in kept}
    dropped = [f for f in candidates if id(f) not in kept_ids]
    certificates = [entry for entry in log if entry.get("drop")]
    if len(dropped) != len(certificates):
        return findings
    by_id = {id(f): cert for f, cert in zip(dropped, certificates)}

    out = []
    for finding in findings:
        cert = by_id.get(id(finding))
        mechanism = str((cert or {}).get("mechanism") or "")
        if cert is None or mechanism in _EXCLUDED_MECHANISMS:
            out.append(finding)
            continue
        record = dict(finding)
        record["category"] = "danger"
        record["reason"] = f"{REASON_PREFIX}: {mechanism}"
        record["refutation"] = {
            "mechanism": mechanism,
            "detail": _json_safe(cert.get("detail") or {}),
        }
        suppressed.append(record)
    return out
