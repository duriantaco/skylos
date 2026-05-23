from __future__ import annotations

import os
from pathlib import Path

from skylos.visitors.languages.csharp import scan_csharp_file


def _write_fixture(path: Path, code: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)  # skylos: ignore[SKY-D215] pytest tmp fixture
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(code)


def _scan_csharp_findings(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "Controller.cs"
    _write_fixture(file_path, code)
    return scan_csharp_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_csharp_symbols_include_import_class_method_and_refs(tmp_path):
    file_path = tmp_path / "Controller.cs"
    _write_fixture(
        file_path,
        """
using System.Net.Http;

public class FetchController {
    public async Task Fetch(string url) {
        var client = new HttpClient();
        await client.GetAsync(url);
    }
}
""",
    )

    defs, refs = scan_csharp_file(str(file_path), {})[:2]

    assert {definition.name for definition in defs} >= {
        "FetchController",
        "FetchController.Fetch",
    }
    assert "GetAsync" in {name for name, _ in refs}


def test_process_start_with_tainted_command_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Diagnostics;

public class JobsController {
    public void Run(string command) {
        Process.Start(command);
    }
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_process_start_with_literal_command_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Diagnostics;

public class JobsController {
    public void Run() {
        Process.Start("dotnet", "--info");
    }
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_process_start_info_property_with_tainted_command_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Diagnostics;

public class JobsController {
    public void Run(string command) {
        var info = new ProcessStartInfo();
        info.FileName = command;
    }
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_regular_file_name_property_assignment_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
public class UploadModel {
    public string FileName { get; set; }
}

public class UploadController {
    public void Save(string fileName) {
        var model = new UploadModel();
        model.FileName = fileName;
    }
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_sql_command_with_tainted_string_concat_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Data.SqlClient;

public class UserRepository {
    public void Find(string userId, SqlConnection connection) {
        var sql = "SELECT * FROM Users WHERE Id = " + userId;
        new SqlCommand(sql, connection);
    }
}
""",
    )
    assert "SKY-D211" in _rule_ids(findings)


def test_sql_command_with_multiline_tainted_string_concat_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Data.SqlClient;

public class UserRepository {
    public void Find(string userId, SqlConnection connection) {
        var sql =
            "SELECT; * FROM Users WHERE Id = " + userId;
        new SqlCommand(sql, connection);
    }
}
""",
    )
    assert "SKY-D211" in _rule_ids(findings)


def test_sql_command_text_property_with_tainted_value_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Data.SqlClient;

public class UserRepository {
    public void Find(string userId, SqlConnection connection) {
        var sql = "SELECT * FROM Users WHERE Id = " + userId;
        var command = new SqlCommand();
        command.CommandText = sql;
    }
}
""",
    )
    assert "SKY-D211" in _rule_ids(findings)


def test_regular_command_text_property_assignment_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
public class UiCommand {
    public string CommandText { get; set; }
}

public class MenuController {
    public void Label(string query) {
        var command = new UiCommand();
        command.CommandText = query;
    }
}
""",
    )
    assert "SKY-D211" not in _rule_ids(findings)


def test_parameterized_sql_literal_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Data.SqlClient;

public class UserRepository {
    public void Find(string userId, SqlConnection connection) {
        var command = new SqlCommand("SELECT * FROM Users WHERE Id = @id", connection);
        command.Parameters.AddWithValue("@id", userId);
    }
}
""",
    )
    assert "SKY-D211" not in _rule_ids(findings)


def test_parameterized_sql_literal_with_id_token_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Data.SqlClient;

public class UserRepository {
    public void Find(int id, SqlConnection connection) {
        var command = new SqlCommand("SELECT * FROM Users WHERE id = @id", connection);
        command.Parameters.AddWithValue("@id", id);
    }
}
""",
    )
    assert "SKY-D211" not in _rule_ids(findings)


def test_http_client_with_tainted_url_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Net.Http;

public class FetchController {
    public async Task Fetch(string url) {
        var client = new HttpClient();
        await client.GetAsync(url);
    }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_http_client_multiline_call_with_tainted_url_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Net.Http;

public class FetchController {
    public async Task Fetch(string url) {
        var client = new HttpClient();
        await client.GetAsync(
            url
        );
    }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_http_client_literal_url_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Net.Http;

public class FetchController {
    public async Task Fetch() {
        var client = new HttpClient();
        await client.GetAsync("https://example.com/health");
    }
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_file_read_with_tainted_path_flags(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.IO;

public class FilesController {
    public string Read(string path) {
        var requested = path;
        return File.ReadAllText(requested);
    }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_path_get_file_name_sanitized_file_path_is_safe(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.IO;

public class FilesController {
    public string Read(string fileName) {
        var safe = Path.GetFileName(fileName);
        return File.ReadAllText(Path.Combine("/srv/data", safe));
    }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_request_query_source_propagates_to_redirect(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using Microsoft.AspNetCore.Mvc;

public class LoginController : Controller {
    public IActionResult Done() {
        var next = Request.Query["next"].ToString();
        return Redirect(next);
    }
}
""",
    )
    assert "SKY-D230" in _rule_ids(findings)


def test_taint_does_not_leak_across_methods(tmp_path):
    findings = _scan_csharp_findings(
        tmp_path,
        """
using System.Diagnostics;
using System.IO;

public class JobsController {
    public void Unsafe(string command) {
        Process.Start(command);
    }

    public string Safe() {
        var path = "/srv/data/report.txt";
        return File.ReadAllText(path);
    }
}
""",
    )
    assert _rule_ids(findings) == {"SKY-D212"}
