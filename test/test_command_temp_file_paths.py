"""SKY-D203: an ``os.system``/``os.popen`` command made only of literals and
paths ``tempfile`` created in the same function reads no outside input, so it
is demoted like a fixed command; anything else interpolated stays listed."""

from pathlib import Path

from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.listing import is_listed
from skylos.rules.danger.danger import scan_ctx


def _commands(tmp_path: Path, code: str) -> dict[int, dict]:
    path = tmp_path / "app" / "convert.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return {
        f["line"]: f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D203"
    }


def _listed(finding: dict) -> bool:
    view = apply_advice_policy({"danger": [finding]})
    return any(is_listed(row, "danger") for row in view["danger"])


_TEMP_ONLY = """\
import os
import tempfile
from tempfile import mkdtemp


def convert(data):
    fd_in, tmp_in = tempfile.mkstemp(suffix=".png")
    tmp_out = tempfile.mkstemp(suffix=".webp")[1]
    os.system(f"cwebp {tmp_in} -o {tmp_out}")
    with tempfile.NamedTemporaryFile(suffix=".txt") as handle:
        os.system(f"wc -l {handle.name}")
    scratch = mkdtemp()
    os.popen(f"ls {scratch}")
    with tempfile.TemporaryDirectory() as workdir:
        os.system("tar xf archive.tar -C " + workdir)
    os.system(f"cat {tempfile.NamedTemporaryFile(delete=False).name}")
"""


def test_command_of_literals_and_temp_paths_is_demoted(tmp_path):
    findings = _commands(tmp_path, _TEMP_ONLY)
    assert sorted(findings) == [9, 11, 13, 15, 16]
    for finding in findings.values():
        assert finding["severity"] == "LOW"
        assert finding["low_risk_context"]["reason"] == "temp-file-command"
        assert not _listed(finding)


_UNTRUSTED = """\
import os
import tempfile
from flask import request


@app.route("/convert")
def convert():
    name = request.args["name"]
    fd, tmp = tempfile.mkstemp()
    os.system(f"convert {name} {tmp}")
    os.system(f"echo {name}")
    fd2, tainted = tempfile.mkstemp(suffix=name)
    os.system(f"cwebp {tainted}")


def helper(path):
    fd, tmp = tempfile.mkstemp()
    os.system(f"cp {path} {tmp}")
    tmp = path
    os.system(f"cat {tmp}")


def rebound():
    fd, out = tempfile.mkstemp()
    out = out + ".bak"
    os.system(f"touch {out}")
    os.system(f"cat {out} $HOME")
"""


def test_request_data_and_other_values_keep_the_finding(tmp_path):
    findings = _commands(tmp_path, _UNTRUSTED)
    assert sorted(findings) == [10, 11, 13, 18, 20, 26, 27]
    for finding in findings.values():
        assert finding["severity"] == "CRITICAL"
        assert "low_risk_context" not in finding
        assert _listed(finding)
