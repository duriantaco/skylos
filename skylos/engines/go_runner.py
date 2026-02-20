import json
import os
import shutil
import subprocess
from pathlib import Path

import skylos
from .go_contract import build_go_engine_args, validate_go_engine_output


DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "dist",
    "build",
}


class GoEngineError(RuntimeError):
    pass


def discover_go_modules(scan_root):
    scan_root = Path(scan_root).resolve()
    modules = []

    if (scan_root / "go.mod").is_file():
        return [scan_root]

    stack = [scan_root]
    while stack:
        cur = stack.pop()

        name = cur.name
        if name in DEFAULT_SKIP_DIRS:
            continue
        if name.startswith(".") and name not in {".", ".."} and name != ".github":
            continue

        go_mod = cur / "go.mod"
        if go_mod.is_file():
            modules.append(cur)
            continue

        try:
            for child in cur.iterdir():
                if child.is_dir():
                    stack.append(child)
        except Exception:
            continue

    modules = sorted(modules, key=lambda p: str(p))
    return modules


def resolve_go_engine_bin():
    override = os.getenv("SKYLOS_GO_BIN")
    if override:
        p = Path(override).expanduser()
        if p.is_file():
            return str(p)
        raise GoEngineError("SKYLOS_GO_BIN is set but binary does not exist: %s" % p)

    exe = "skylos-go.exe" if os.name == "nt" else "skylos-go"
    found = shutil.which(exe) or shutil.which("skylos-go")
    if found:
        return found

    raise GoEngineError(
        "Go engine binary not found (skylos-go).\n"
        "Build it locally:\n"
        "  cd engines/go && go build -o skylos-go ./cmd/skylos-go\n"
        "Then set:\n"
        "  export SKYLOS_GO_BIN=/absolute/path/to/skylos-go"
    )


def run_go_engine_for_module(module_root, timeout_s=60):
    engine_bin = resolve_go_engine_bin()
    module_root = Path(module_root).resolve()

    argv = build_go_engine_args(
        engine_bin=engine_bin,
        root=str(module_root),
        skylos_version=str(skylos.__version__),
    )

    try:
        proc = subprocess.run(
            argv,
            cwd=str(module_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GoEngineError(
            "Go engine timed out after %ss for module: %s" % (timeout_s, module_root)
        )
    except Exception as e:
        raise GoEngineError("Failed to run Go engine: %s" % e)

    if proc.returncode != 0:
        raise GoEngineError(
            "Go engine failed.\n"
            "Command: %s\n"
            "Exit code: %s\n"
            "STDERR:\n%s"
            % (" ".join(argv), proc.returncode, (proc.stderr or "").strip())
        )

    try:
        obj = json.loads(proc.stdout or "")
    except Exception as e:
        raise GoEngineError(
            "Go engine returned invalid JSON.\n"
            "STDOUT:\n%s\n"
            "STDERR:\n%s\n"
            "Error: %s" % ((proc.stdout or "").strip(), (proc.stderr or "").strip(), e)
        )

    out = validate_go_engine_output(obj)
    return list(out.get("findings", []))


def run_go_engine(scan_root, timeout_s=60):
    modules = discover_go_modules(scan_root)
    if not modules:
        return []

    all_findings = []
    for module_root in modules:
        all_findings.extend(run_go_engine_for_module(module_root, timeout_s=timeout_s))
    return all_findings
