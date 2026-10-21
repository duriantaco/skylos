from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules import catalog


def run_parity(tmp_path, monkeypatch, docs_ids, catalog_ids, *flags):
    reference = tmp_path / "rules-reference.mdx"
    assert write_text_no_symlink(reference, "\n".join(docs_ids), encoding="utf-8")
    monkeypatch.setattr(
        catalog, "get_rule_catalog", lambda: [{"id": item} for item in catalog_ids]
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["check_rule_docs_parity", "--rules-reference", str(reference), *flags],
    )
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "check_rule_docs_parity.py"
    )
    spec = importlib.util.spec_from_file_location("rule_docs_parity", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main()


def test_extra_docs_fail_by_default(tmp_path, monkeypatch, capsys):
    result = run_parity(tmp_path, monkeypatch, ["SKY-D215", "SKY-D324"], ["SKY-D215"])
    assert result == 1
    assert "Docs IDs missing from catalog:\n  SKY-D324" in capsys.readouterr().out


def test_explicit_extra_docs_option_allows_ahead_documentation(
    tmp_path, monkeypatch, capsys
):
    result = run_parity(
        tmp_path,
        monkeypatch,
        ["SKY-D215", "SKY-D324"],
        ["SKY-D215"],
        "--allow-docs-extra",
    )
    output = capsys.readouterr().out
    assert result == 0
    assert "Additional documented IDs outside this catalog:\n  SKY-D324" in output
    assert "All catalog rule IDs are documented." in output


def test_extra_docs_option_still_rejects_missing_documentation(
    tmp_path, monkeypatch, capsys
):
    result = run_parity(
        tmp_path, monkeypatch, ["SKY-D324"], ["SKY-D215"], "--allow-docs-extra"
    )
    assert result == 1
    assert "Catalog IDs missing from docs:\n  SKY-D215" in capsys.readouterr().out
