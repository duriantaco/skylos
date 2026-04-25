from __future__ import annotations

import os
from pathlib import Path

import pytest

from skylos.engines.go_runner import GoEngineError, resolve_go_engine_bin
from skylos.visitors.languages.go import clear_go_cache, scan_go_file


@pytest.fixture(autouse=True)
def _pin_repo_go_engine(monkeypatch):
    engine_name = "skylos-go.exe" if os.name == "nt" else "skylos-go"
    engine_bin = (
        Path(__file__).resolve().parent.parent / "skylos" / "engines" / "go" / engine_name
    )
    if not engine_bin.is_file():
        pytest.skip("repo skylos-go engine binary not available")
    monkeypatch.setenv("SKYLOS_GO_BIN", str(engine_bin))
    clear_go_cache()


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


def test_exec_command_shell_concat_flags_command_injection(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(name string) error {
    return exec.Command("sh", "-c", "git " + name).Run()
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_exec_command_bash_login_shell_concat_flags_command_injection(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(name string) error {
    return exec.Command("bash", "-lc", "git " + name).Run()
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_exec_command_bash_option_operand_concat_flags_command_injection(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(name string) error {
    return exec.Command("bash", "-o", "pipefail", "-c", "git " + name).Run()
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_exec_command_powershell_command_flags_command_injection(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(script string) error {
    return exec.Command("powershell", "-NoProfile", "-Command", script).Run()
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_exec_command_windows_cmd_path_flags_command_injection(tmp_path):
    findings = _scan_go(
        tmp_path,
        r"""package main

import "os/exec"

func run(name string) error {
    return exec.Command(`C:\Windows\System32\cmd.exe`, "/c", "git " + name).Run()
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_exec_command_shell_positional_arg_is_safe(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(branch string) error {
    return exec.Command("sh", "-c", `git checkout -- "$1"`, "sh", branch).Run()
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_exec_command_shell_script_arg_with_dash_c_is_safe(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(user string) error {
    return exec.Command("sh", "script.sh", "-c", user).Run()
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_exec_command_powershell_file_arg_with_command_is_safe(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(user string) error {
    return exec.Command("powershell", "-File", "script.ps1", "-Command", user).Run()
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_exec_command_constant_binary_variable_argv_is_safe(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import "os/exec"

func run(name string) error {
    return exec.Command("git", name).Run()
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


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


def test_zip_slip_filepath_islocal_guard_is_safe(tmp_path):
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
        if !filepath.IsLocal(file.Name) {
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


def test_zip_slip_filepath_islocal_alias_guard_is_safe(tmp_path):
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
        ok := filepath.IsLocal(file.Name)
        if !ok {
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


def test_zip_slip_filepath_islocal_noop_still_flags(tmp_path):
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
        _ = filepath.IsLocal(file.Name)
        target := filepath.Join(dest, file.Name)
        out, _ := os.Create(target)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_combined_guard_is_safe(tmp_path):
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
        if !filepath.IsLocal(file.Name) || strings.Contains(file.Name, "..") {
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


def test_zip_slip_reassigned_guard_alias_still_flags(tmp_path):
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
        ok := filepath.IsLocal(file.Name)
        ok = true
        if !ok {
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
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_clean_prefix_guard_is_safe(tmp_path):
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
    cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
    for _, file := range reader.File {
        target := filepath.Join(dest, file.Name)
        cleaned := filepath.Clean(target)
        if !strings.HasPrefix(cleaned, cleanDest) {
            continue
        }
        out, _ := os.Create(cleaned)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_zip_slip_reassigned_guarded_name_still_flags(tmp_path):
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
        name := file.Name
        if strings.Contains(name, "..") {
            continue
        }
        name = filepath.Base(file.Name) + file.Name
        target := filepath.Join(dest, name)
        out, _ := os.Create(target)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_break_guard_is_safe(tmp_path):
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
            break
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


def test_tar_fs_validpath_is_not_treated_as_safe_guard(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/tar"
    "io/fs"
    "os"
    "path/filepath"
)

func untar(reader *tar.Reader, dest string) error {
    for {
        header, err := reader.Next()
        if err != nil {
            return err
        }
        if !fs.ValidPath(header.Name) {
            continue
        }
        target := filepath.Join(dest, header.Name)
        out, _ := os.Create(target)
        _ = out
    }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_new_tainted_alias_after_guard_still_flags(tmp_path):
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
        if !filepath.IsLocal(file.Name) {
            continue
        }
        name := "../" + file.Name
        target := filepath.Join(dest, name)
        out, _ := os.Create(target)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_sink_inside_switch_is_detected(tmp_path):
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
        switch {
        default:
            out, _ := os.Create(target)
            _ = out
        }
    }
    return nil
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_zip_slip_strings_cut_second_result_still_flags(tmp_path):
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
        _, name, _ := strings.Cut(file.Name, "/")
        target := filepath.Join(dest, name)
        out, _ := os.Create(target)
        _ = out
    }
    return nil
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_tar_symlink_extraction_flags(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/tar"
    "os"
    "path/filepath"
)

func untar(reader *tar.Reader, dest string) error {
    for {
        header, err := reader.Next()
        if err != nil {
            return err
        }
        if header.Typeflag != tar.TypeSymlink {
            continue
        }
        target := filepath.Join(dest, header.Name)
        _ = os.Symlink(header.Linkname, target)
    }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_tar_symlink_rel_guard_without_evalsymlinks_still_flags(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/tar"
    "os"
    "path/filepath"
    "strings"
)

func untar(reader *tar.Reader, dest string) error {
    cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
    for {
        header, err := reader.Next()
        if err != nil {
            return err
        }
        if header.Typeflag != tar.TypeSymlink {
            continue
        }
        target := filepath.Join(dest, header.Name)
        cleanTarget := filepath.Clean(target)
        if !strings.HasPrefix(cleanTarget, cleanDest) {
            continue
        }
        linkTarget := filepath.Join(dest, header.Linkname)
        relTarget, _ := filepath.Rel(dest, linkTarget)
        if strings.HasPrefix(relTarget, "..") {
            continue
        }
        _ = os.Symlink(linkTarget, cleanTarget)
    }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_tar_symlink_evalsymlinks_rel_guard_is_safe(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/tar"
    "os"
    "path/filepath"
    "strings"
)

func untar(reader *tar.Reader, dest string) error {
    cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
    for {
        header, err := reader.Next()
        if err != nil {
            return err
        }
        if header.Typeflag != tar.TypeSymlink {
            continue
        }
        target := filepath.Join(dest, header.Name)
        cleanTarget := filepath.Clean(target)
        if !strings.HasPrefix(cleanTarget, cleanDest) {
            continue
        }
        linkTarget := filepath.Join(dest, header.Linkname)
        resolvedTarget, err := filepath.EvalSymlinks(linkTarget)
        if err != nil {
            continue
        }
        relTarget, err := filepath.Rel(dest, resolvedTarget)
        if err != nil {
            continue
        }
        if strings.HasPrefix(relTarget, "..") {
            continue
        }
        _ = os.Symlink(resolvedTarget, cleanTarget)
    }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_tar_symlink_mixed_safe_and_unsafe_still_flags(tmp_path):
    findings = _scan_go(
        tmp_path,
        """package main

import (
    "archive/tar"
    "os"
    "path/filepath"
    "strings"
)

func untar(reader *tar.Reader, dest string) error {
    cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
    for {
        header, err := reader.Next()
        if err != nil {
            return err
        }
        if header.Typeflag != tar.TypeSymlink {
            continue
        }
        target := filepath.Join(dest, header.Name)
        cleanTarget := filepath.Clean(target)
        if !strings.HasPrefix(cleanTarget, cleanDest) {
            continue
        }
        if strings.HasPrefix(header.Name, "safe/") {
            linkTarget := filepath.Join(dest, header.Linkname)
            resolvedTarget, err := filepath.EvalSymlinks(linkTarget)
            if err != nil {
                continue
            }
            relTarget, err := filepath.Rel(dest, resolvedTarget)
            if err != nil {
                continue
            }
            if strings.HasPrefix(relTarget, "..") {
                continue
            }
            _ = os.Symlink(resolvedTarget, cleanTarget)
            continue
        }
        _ = os.Symlink(header.Linkname, cleanTarget)
    }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)
