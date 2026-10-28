import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file


def project(tmp_path, source):
    path = tmp_path / "src" / "main.rs"
    path.parent.mkdir()
    path.write_text(dedent(source).lstrip())
    return path


def unused(tmp_path, **options):
    report = json.loads(analyze(str(tmp_path), **options))
    return {item["full_name"]: item for item in report["unused_functions"]}


@pytest.mark.parametrize("method", ["clone", "default", "call", "poll"])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_unused_private_inherent_method_is_not_an_implicit_entry(
    tmp_path, method, grep_verify
):
    path = project(
        tmp_path,
        f"""
        struct Worker;
        impl Worker {{ fn {method}(&self) {{}} }}
        fn main() {{ let _worker = Worker; }}
    """,
    )
    definitions = {d.name: d for d in scan_rust_file(str(path), {})[0]}
    assert not definitions[f"Worker.{method}"].is_exported
    findings = unused(tmp_path, conf=40, grep_verify=grep_verify)
    assert f"Worker.{method}" in findings
    assert findings[f"Worker.{method}"]["confidence"] <= 40
    # Rust remains experimental: no new default-threshold promises.
    assert f"Worker.{method}" not in unused(tmp_path, grep_verify=grep_verify)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_inherent_method_call_preserves_exact_owner(tmp_path, grep_verify):
    project(
        tmp_path,
        """
        struct Active;
        struct Dormant;
        impl Active { fn call(&self) {} }
        impl Dormant { fn call(&self) {} }
        fn main() {
            let active = Active;
            let _dormant = Dormant;
            active.call();
        }
    """,
    )
    findings = unused(tmp_path, conf=40, grep_verify=grep_verify)
    assert "Active.call" not in findings
    assert "Dormant.call" in findings


def test_trait_implementation_and_public_api_remain_entries(tmp_path):
    path = project(
        tmp_path,
        """
        struct Worker;
        impl Clone for Worker { fn clone(&self) -> Self { Self } }
        impl Worker { pub fn call(&self) {} }
        fn main() { let _worker = Worker; }
    """,
    )
    definitions = {d.name: d for d in scan_rust_file(str(path), {})[0]}
    assert definitions["Worker.clone"].is_exported
    assert definitions["Worker.call"].is_exported
    findings = unused(tmp_path, conf=40, grep_verify=False)
    assert "Worker.clone" not in findings
    assert "Worker.call" not in findings


def test_method_called_only_from_dead_helper_remains_dead(tmp_path):
    project(
        tmp_path,
        """
        struct Worker;
        impl Worker { fn call(&self) {} }
        fn abandoned() { Worker.call(); }
        fn main() {}
    """,
    )
    findings = unused(tmp_path, conf=40, grep_verify=False)
    assert "abandoned" in findings
    assert "Worker.call" in findings
