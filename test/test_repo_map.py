from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "build_repo_map.py"


def _load_repo_map_module():
    spec = importlib.util.spec_from_file_location("build_repo_map", SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_collect_repo_map_extracts_routes_and_symbols(tmp_path):
    repo_map = _load_repo_map_module()
    _write(
        tmp_path / "skylos" / "cli.py",
        '"""Command line entrypoint."""\n\n'
        "class Runner:\n"
        "    pass\n\n"
        "def main():\n"
        "    return Runner()\n",
    )
    _write(
        tmp_path / "skylos" / "llm" / "analyzer.py",
        "def review_security_scan_result():\n"
        "    return []\n",
    )
    _write(tmp_path / "test" / "test_llm.py", "def test_llm_path():\n    assert True\n")

    data = repo_map.collect_repo_map(tmp_path)

    assert data["python_file_count"] == 3
    assert data["symbol_count"] == 4
    folder_paths = {card["path"] for card in data["folder_cards"]}
    assert {"skylos", "skylos/llm", "test"}.issubset(folder_paths)
    symbol_names = {item["name"] for item in data["symbol_index"]}
    assert {"Runner", "main", "review_security_scan_result"}.issubset(symbol_names)


def test_render_html_prioritizes_start_routes_and_search(tmp_path):
    repo_map = _load_repo_map_module()
    _write(tmp_path / "skylos" / "config.py", "def load_config():\n    return {}\n")
    _write(tmp_path / "dictionary.md", "# Rules\n")
    _write(tmp_path / "test" / "test_config.py", "def test_config():\n    assert True\n")
    data = repo_map.collect_repo_map(tmp_path)

    page = repo_map.render_html(data)

    assert "Skylos Map" in page
    assert "Start Here" in page
    assert "Choose A Mode" in page
    assert "Architecture" in page
    assert "Docstring Standard" in page
    assert "First 10 Minutes" in page
    assert "Current mode" in page
    assert "active-mode-plan" in page
    assert "Safe Path" in page
    assert "I am debugging a bad finding" in page
    assert "Trust Boundary" in page
    assert "I want to understand a normal scan" in page
    assert "repo-search" in page
    assert "load_config" in page
    assert 'href="../../' not in page
    assert "https://github.com/duriantaco/skylos/blob/main/dictionary.md" in page
    assert "https://github.com/duriantaco/skylos/tree/main/test" in page


def test_main_check_detects_stale_output(tmp_path):
    repo_map = _load_repo_map_module()
    _write(tmp_path / "skylos" / "config.py", "def load_config():\n    return {}\n")
    output = tmp_path / "docs" / "repo-map" / "index.html"

    assert repo_map.main(["--root", str(tmp_path), "--output", str(output)]) == 0
    assert repo_map.main(["--root", str(tmp_path), "--output", str(output), "--check"]) == 0

    output.write_text("stale", encoding="utf-8")

    assert repo_map.main(["--root", str(tmp_path), "--output", str(output), "--check"]) == 1


def test_main_check_ignores_line_only_source_churn(tmp_path):
    repo_map = _load_repo_map_module()
    source = tmp_path / "skylos" / "config.py"
    _write(source, "def load_config():\n    return {}\n")
    output = tmp_path / "docs" / "repo-map" / "index.html"

    assert repo_map.main(["--root", str(tmp_path), "--output", str(output)]) == 0

    line_noise = "\n".join("# implementation note" for _ in range(700))
    source.write_text(f"{line_noise}\n\ndef load_config():\n    return {{}}\n", encoding="utf-8")

    assert repo_map.main(["--root", str(tmp_path), "--output", str(output), "--check"]) == 0
