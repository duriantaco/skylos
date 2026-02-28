from pathlib import Path
from skylos.engines.go_runner import run_go_engine_for_module

# Remap Go-specific rule IDs to unified cross-language IDs.
# Go-only rules (no Python/TS equivalent) keep their original IDs.
_GO_RULE_REMAP = {
    "SKY-G211": "SKY-D211",  # SQL injection
    "SKY-G212": "SKY-D212",  # Command injection
    "SKY-G215": "SKY-D215",  # Path traversal
    "SKY-G216": "SKY-D216",  # SSRF
    "SKY-G207": "SKY-D207",  # Weak hash MD5
    "SKY-G208": "SKY-D208",  # Weak hash SHA1
    "SKY-G210": "SKY-D210",  # TLS verification disabled
    "SKY-G220": "SKY-D230",  # Open redirect
}


def scan_go_file(file_path, cfg):
    file_path = Path(file_path)

    module_root = _find_module_root(file_path)

    if not module_root:
        module_root = file_path.parent

    try:
        findings = run_go_engine_for_module(module_root)
    except Exception as e:
        import os

        if os.getenv("SKYLOS_DEBUG"):
            print(f"Go analysis failed: {e}")
        return ([], [], set(), set(), None, None, [], [], [], None, None, cfg, [])

    file_findings = [
        f for f in findings if Path(f.get("file", "")).resolve() == file_path.resolve()
    ]

    for f in file_findings:
        rid = f.get("rule_id", "")
        if rid in _GO_RULE_REMAP:
            f["rule_id"] = _GO_RULE_REMAP[rid]

    return (
        [],
        [],
        set(),
        set(),
        None,
        None,
        [],
        file_findings,
        [],
        None,
        None,
        cfg,
        [],
    )


def _find_module_root(file_path):
    current = Path(file_path).parent
    while current != current.parent:
        if (current / "go.mod").exists():
            return current
        current = current.parent
    return None
