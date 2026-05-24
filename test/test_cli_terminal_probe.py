import os
import subprocess
import sys

import skylos


def test_version_does_not_import_inquirer_at_startup(tmp_path):
    fake_probe = (
        "+q544e+q524742+q636f6c6f7273+q626c696e6b+q7369746d"
        "+q7269746d+q6376766973+q536d756c78+q536574756c63+q4d73"
    )
    (tmp_path / "inquirer.py").write_text(
        "import sys\n" f"sys.stdout.write({fake_probe!r})\n", encoding="utf-8"
    )

    repo_root = os.path.dirname(os.path.dirname(__file__))
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path), repo_root, env.get("PYTHONPATH", "")]
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.argv=['skylos', '--version']; "
            "from skylos.cli import main; main()",
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert fake_probe not in completed.stdout
    assert completed.stdout.strip() == f"skylos {skylos.__version__}"


def test_concise_gate_exit_code_does_not_import_inquirer(tmp_path):
    fake_probe = (
        "+q544e+q524742+q636f6c6f7273+q626c696e6b+q7369746d"
        "+q7269746d+q6376766973+q536d756c78+q536574756c63+q4d73"
    )
    (tmp_path / "inquirer.py").write_text(
        "import sys\n" f"sys.stdout.write({fake_probe!r})\n", encoding="utf-8"
    )

    repo_root = os.path.dirname(os.path.dirname(__file__))
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path), repo_root, env.get("PYTHONPATH", "")]
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from types import SimpleNamespace; "
            "from skylos.cli import _concise_scan_exit_code; "
            "args=SimpleNamespace(gate=True, strict=False, summary=False, force=False); "
            "result={'quality':[{'file':'app.py','line':1,'severity':'high'}]}; "
            "raise SystemExit(_concise_scan_exit_code(result, {'gate': {'max_quality': 0}}, args))",
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 1
    assert fake_probe not in completed.stdout
    assert completed.stdout == ""
