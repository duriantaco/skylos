from __future__ import annotations

from pathlib import Path

import pytest

from skylos.engines.go_runner import GoEngineError, resolve_go_engine_bin
from skylos.visitors.languages.go import clear_go_cache, scan_go_file


def _scan_go(tmp_path: Path, code: str) -> list[dict]:
    try:
        resolve_go_engine_bin()
    except GoEngineError:
        pytest.skip("skylos-go engine binary not available")

    (tmp_path / "go.mod").write_text(
        "module example.com/demo\n\ngo 1.22\n",
        encoding="utf-8",
    )
    file_path = tmp_path / "main.go"
    file_path.write_text(code, encoding="utf-8")
    clear_go_cache()
    return scan_go_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_math_rand_remapped_to_shared_rule(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "math/rand"

func main() {
    _ = rand.Int()
}
""",
    )
    assert "SKY-D250" in _rule_ids(findings)


def test_insecure_cookie_remapped_to_shared_rule(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "net/http"

func main() {
    _ = http.Cookie{Name: "sid", Value: "x", Secure: true}
}
""",
    )
    assert "SKY-D252" in _rule_ids(findings)


def test_weak_tls_version_still_reported(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "crypto/tls"

func main() {
    _ = tls.Config{MinVersion: tls.VersionTLS10}
}
""",
    )
    assert "SKY-G280" in _rule_ids(findings)


def test_zip_slip_archive_extraction_flags(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/zip"
    "os"
    "path/filepath"
)

func unzip(path string, dest string) error {
    reader, _ := zip.OpenReader(path)
    for _, file := range reader.File {
        target := filepath.Join(dest, file.Name)
        out, _ := os.Create(target)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_guarded_entry_name_is_safe(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/zip"
    "os"
    "path/filepath"
    "strings"
)

func unzip(path string, dest string) error {
    reader, _ := zip.OpenReader(path)
    for _, file := range reader.File {
        if strings.Contains(file.Name, "..") {
            continue
        }
        target := filepath.Join(dest, file.Name)
        out, _ := os.Create(target)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)
