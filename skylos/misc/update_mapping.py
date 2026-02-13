from __future__ import annotations

import re
import site
import subprocess
import sys
from pathlib import Path


MAPPING_FILE = Path(__file__).with_name("pipreqs_import_mapping.txt")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def load_existing():
    mapping = {}
    if not MAPPING_FILE.exists():
        return mapping
    for line in MAPPING_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        imp, dist = line.split(":", 1)
        imp, dist = imp.strip(), dist.strip()
        if imp and dist:
            mapping[imp] = dist
    return mapping


def bootstrap_from_pipreqs():
    pipreqs_mapping = _find_pipreqs_mapping()

    if not pipreqs_mapping:
        print("Installing pipreqs to get the community mapping...")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "pipreqs",
                "-q",
                "--break-system-packages",
            ],
            capture_output=True,
        )
        pipreqs_mapping = _find_pipreqs_mapping()

    if not pipreqs_mapping:
        print("ERROR: Could not find pipreqs mapping file after install.")
        print("You can manually download it from:")
        print("  https://github.com/bndr/pipreqs/blob/master/pipreqs/mapping")
        return

    content = pipreqs_mapping.read_text(encoding="utf-8", errors="ignore")
    MAPPING_FILE.write_text(content, encoding="utf-8")

    count = sum(
        1
        for line in content.splitlines()
        if line.strip() and ":" in line and not line.startswith("#")
    )
    print(f"Bootstrapped {count} entries from pipreqs mapping.\n")


def _find_pipreqs_mapping() -> Path | None:
    try:
        import pipreqs

        candidate = Path(pipreqs.__file__).with_name("mapping")
        if candidate.exists():
            return candidate
    except ImportError:
        pass

    sp_dirs = []
    try:
        sp_dirs.extend(site.getsitepackages())
    except Exception:
        pass
    try:
        user_sp = site.getusersitepackages()
        if user_sp:
            sp_dirs.append(user_sp)
    except Exception:
        pass

    for sp_dir in sp_dirs:
        candidate = Path(sp_dir) / "pipreqs" / "mapping"
        if candidate.exists():
            return candidate

    return None


def get_stdlib():
    std = getattr(sys, "stdlib_module_names", None)
    if std:
        return set(std)
    return {
        "os",
        "sys",
        "re",
        "json",
        "math",
        "time",
        "typing",
        "pathlib",
        "subprocess",
        "collections",
        "functools",
        "itertools",
        "logging",
        "datetime",
        "hashlib",
        "random",
        "threading",
        "http",
        "urllib",
        "email",
        "socket",
        "unittest",
        "dataclasses",
        "asyncio",
        "base64",
        "html",
        "shlex",
        "shelve",
        "marshal",
        "site",
        "io",
        "zipfile",
        "argparse",
        "abc",
        "copy",
        "csv",
        "struct",
        "enum",
        "contextlib",
        "signal",
        "shutil",
        "tempfile",
        "glob",
        "stat",
        "string",
        "warnings",
    }


STDLIB = get_stdlib()

SKIP = {
    "__pycache__",
    "tests",
    "test",
    "bin",
    "scripts",
    "_vendor",
    "_internal",
    "pip",
    "pkg_resources",
    "setuptools",
    "wheel",
    "distutils",
    "ensurepip",
    "venv",
    "LICENSE",
    "LICENCE",
    "NOTICE",
    "README",
    "CHANGELOG",
    "AUTHORS",
    "CONTRIBUTING",
    "MANIFEST",
    "Makefile",
    "setup",
}

_JUNK_RE = re.compile(
    r"^test_"
    r"|^tests_"
    r"|__mypyc$"
    r"|^_[0-9a-f]{8}"
    r"|[0-9a-f]{16}"
)


def scan():
    discoveries = {}

    try:
        from importlib.metadata import packages_distributions

        for module, dists in packages_distributions().items():
            if module in STDLIB or module in SKIP or module.startswith("_"):
                continue
            if _JUNK_RE.search(module):
                continue
            for dist in dists:
                if _normalize(module) != _normalize(dist):
                    discoveries[module] = dist
    except ImportError:
        pass

    sp_dirs = []
    try:
        sp_dirs.extend(site.getsitepackages())
    except Exception:
        pass
    try:
        user_sp = site.getusersitepackages()
        if user_sp:
            sp_dirs.append(user_sp)
    except Exception:
        pass

    for sp_dir in sp_dirs:
        sp_path = Path(sp_dir)
        if not sp_path.exists():
            continue

        for dist_info in sp_path.glob("*.dist-info"):
            dist_name = None
            meta = dist_info / "METADATA"
            if meta.exists():
                try:
                    for line in meta.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines():
                        if line.startswith("Name:"):
                            dist_name = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass

            if not dist_name:
                continue

            top_level = dist_info / "top_level.txt"
            if not top_level.exists():
                continue

            try:
                modules = [
                    m.strip()
                    for m in top_level.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                    if m.strip() and not m.strip().startswith("_")
                ]
            except Exception:
                continue

            for mod in modules:
                if mod in STDLIB or mod in SKIP:
                    continue
                if _JUNK_RE.search(mod):
                    continue
                if _normalize(mod) != _normalize(dist_name):
                    if mod not in discoveries:
                        discoveries[mod] = dist_name

    return discoveries


def main():
    existing = load_existing()
    if len(existing) < 100:
        print("Mapping file missing or too small. Bootstrapping from pipreqs...\n")
        bootstrap_from_pipreqs()
        existing = load_existing()

    print(f"Current mapping: {len(existing)} entries")

    discoveries = scan()

    new = {}
    for imp, dist in sorted(discoveries.items()):
        if imp in existing:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", imp):
            continue
        if _JUNK_RE.search(imp):
            continue
        if imp.isupper() and len(imp) <= 10:
            continue
        new[imp] = dist

    if not new:
        print("Already up to date. Nothing to add.")
        return

    print(f"Found {len(new)} new entries:\n")
    for imp, dist in sorted(new.items()):
        print(f"  {imp}:{dist}")

    with open(MAPPING_FILE, "a", encoding="utf-8") as f:
        f.write("\n# Auto-discovered\n")
        for imp, dist in sorted(new.items()):
            f.write(f"{imp}:{dist}\n")

    print(f"\nDone. Mapping now has {len(existing) + len(new)} entries.")


if __name__ == "__main__":
    main()
