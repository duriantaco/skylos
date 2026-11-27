"""Exercise ASP.NET route registrations through the project analyzer."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze

WEB_PROJECT = '<Project Sdk="Microsoft.NET.Sdk.Web" />'
STARTUP = """using Demo.Routes;
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
"""
HANDLERS = """namespace Demo.Routes;
public static class Endpoints
{
    public static Task<string> Lookup(string url, HttpClient client)
    {
        return client.GetStringAsync(url);
    }

    public static Task<string> Fixed(string url, HttpClient client)
    {
        return client.GetStringAsync("https://example.org/health");
    }
}
"""


def write_files(root, files):
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def ssrf_sites(root, **scan_options):
    report = json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, **scan_options)
    )
    assert not report.get("analysis_errors")
    assert report["analysis_summary"]["total_files"] > 0
    return sorted(
        (Path(item["file"]).relative_to(root).as_posix(), item["line"])
        for item in report.get("danger", [])
        if item["rule_id"] == "SKY-D216"
    )


@pytest.mark.parametrize("jobs", [1, 2])
def test_named_handler_is_reported_once_and_tracks_registration_changes(
    tmp_path, monkeypatch, jobs
):
    # Exercise both the in-process and process-pool paths used by the CLI.
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("SKYLOS_JOBS", str(jobs))
    write_files(
        tmp_path,
        {
            "Web.csproj": WEB_PROJECT,
            "Program.cs": STARTUP + 'app.MapGet("/lookup", Endpoints.Lookup);\n'
            'app.MapPost("/also-lookup", Endpoints.Lookup);\n'
            'app.MapGet("/fixed", Endpoints.Fixed);',
            "Handlers/Endpoints.cs": HANDLERS,
            "Other/Endpoints.cs": HANDLERS.replace("Demo.Routes", "Demo.Other"),
        },
    )
    assert ssrf_sites(tmp_path) == [("Handlers/Endpoints.cs", 6)]

    write_files(
        tmp_path, {"Program.cs": STARTUP + 'app.MapGet("/fixed", Endpoints.Fixed);'}
    )
    assert ssrf_sites(tmp_path) == []


def test_sibling_web_projects_and_an_excluded_file_cannot_supply_handlers(tmp_path):
    write_files(
        tmp_path,
        {
            "A/A.csproj": WEB_PROJECT,
            "A/Program.cs": STARTUP + 'app.MapGet("/lookup", Endpoints.Lookup);',
            "A/excluded/Endpoints.cs": HANDLERS,
            "B/B.csproj": WEB_PROJECT,
            "B/Endpoints.cs": HANDLERS,
        },
    )
    assert ssrf_sites(tmp_path, exclude_folders=["excluded"]) == []


def test_route_groups_and_injected_lambda_services(tmp_path):
    write_files(
        tmp_path,
        {
            "Web.csproj": WEB_PROJECT,
            "Program.cs": "using Microsoft.AspNetCore.Mvc;\n"
            + STARTUP
            + 'var group = app.MapGroup("/api");\n'
            'group.MapGet("/lookup", Endpoints.Lookup);\n'
            'app.MapGet("/fixed", ([FromServices] Settings settings, HttpClient client) => client.GetStringAsync(settings.Url));',
            "Handlers/Endpoints.cs": HANDLERS,
            "Settings.cs": 'public sealed class Settings { public string Url { get; set; } = "https://example.org/"; }',
        },
    )
    assert ssrf_sites(tmp_path) == [("Handlers/Endpoints.cs", 6)]


def test_delegate_cast_preserves_the_registered_lambda(tmp_path):
    write_files(
        tmp_path,
        {
            "Web.csproj": WEB_PROJECT,
            "Program.cs": """using System;
var app = WebApplication.Create(args);
app.MapGet("/lookup", (System.Func<string, HttpClient, Task<string>>)(
    (string url, HttpClient client) => client.GetStringAsync(url)));
app.MapGet("/fixed", (Func<HttpClient, Task<string>>)(
    (HttpClient client) => client.GetStringAsync("https://example.org/health")));
""",
        },
    )
    assert ssrf_sites(tmp_path) == [("Program.cs", 4)]


@pytest.mark.parametrize(
    "handler",
    [
        "Endpoints.Lookup",
        "(string url, HttpClient client) => client.GetStringAsync(url)",
    ],
)
def test_unrelated_mapget_never_registers_request_input(tmp_path, handler):
    write_files(
        tmp_path,
        {
            "Web.csproj": WEB_PROJECT,
            "Program.cs": STARTUP
            + "var table = new LocalTable();\n"
            + f'table.MapGet("local", {handler});',
            "Handlers/Endpoints.cs": HANDLERS,
            "LocalTable.cs": """public class LocalTable
{
    public void MapGet(string key, Func<string, HttpClient, Task<string>> callback) {}
}
""",
        },
    )
    assert ssrf_sites(tmp_path) == []
