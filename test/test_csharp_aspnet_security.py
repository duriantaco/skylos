from __future__ import annotations

import pytest

from skylos.rules.catalog import _SECURITY_RULE_CWES
from skylos.visitors.languages.csharp.danger import scan_danger


def _rules(source: str) -> list[tuple[str, str]]:
    return [
        (finding["rule_id"], finding["severity"])
        for finding in scan_danger("App.cs", source)
    ]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "public class JobRunner { public void Run(string c) { Process.Start(c); } }",
            [],
        ),
        (
            "public class JobsController : Controller { "
            "public void Run(string c) { Process.Start(c); } }",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "[ApiController] public class Jobs : BaseApi { "
            "public void Run(string c) { Process.Start(c); } }",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "public class JobsController : Controller { "
            "public JobsController(string c) { Process.Start(c); } }",
            [],
        ),
        (
            "public class JobsController : IDisposable { "
            "public void Run(string c) { Process.Start(c); } }",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "public class PlayerController : MonoBehaviour { "
            "public void Run(string c) { Process.Start(c); } }",
            [],
        ),
        (
            "public class JobsController : Controller { "
            "[NonAction] public void Run(string c) { Process.Start(c); } }",
            [],
        ),
        (
            "public class JobsController : Controller { "
            "private void Run(string c) { Process.Start(c); } }",
            [],
        ),
        (
            "public class JobsController : Controller { public void Run("
            "[FromServices] Catalog c) { Process.Start(c.Tool); } }",
            [],
        ),
        (
            "public class JobsController : Controller { "
            'public void Run(int c) { Process.Start("tool", c.ToString()); } }',
            [],
        ),
        (
            "public static class Handlers { "
            "public static void Run([FromQuery] string c) { Process.Start(c); } }",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "public class ExportModel : PageModel { "
            "public void OnGet(string c) { Process.Start(c); } }",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "public class ExportModel : PageModel { [BindProperty] public string Name "
            "{ get; set; } public string Other { get; set; } "
            "public void OnPost() { File.Delete(Name); File.Delete(Other); } }",
            [("SKY-D215", "HIGH")],
        ),
        (
            "public class ChatHub : Hub { "
            "public void Send(string c) { Process.Start(c); } }",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            'app.MapGet("/f", async (string url, HttpClient http) => '
            "await http.GetStringAsync(url));",
            [("SKY-D216", "CRITICAL")],
        ),
        (
            "public class Audit { public void Invoke(HttpContext context) { "
            'File.Delete(context.Request.Query["f"]); } }',
            [("SKY-D215", "HIGH")],
        ),
    ],
)
def test_request_sources_are_framework_entry_points_not_every_parameter(
    source, expected
):
    assert _rules(source) == expected


def test_same_file_helper_called_with_request_data_reports_its_sink():
    source = (
        "public class BuildController : Controller {\n"
        "  private readonly Repository _links;\n"
        "  public void Start(string target) { RunTool(target); _links.Fetch(target); }\n"
        '  public void Safe() { RunTool("dotnet"); }\n'
        "  private void RunTool(string tool) {\n"
        "    Process.Start(tool);\n"
        "  }\n"
        "}\n"
        "public class Repository {\n"
        "  private readonly HttpClient _client;\n"
        "  public Task<string> Fetch(string url) {\n"
        "    return _client.GetStringAsync(url);\n"
        "  }\n"
        "}\n"
    )

    assert [
        (finding["rule_id"], finding["line"])
        for finding in scan_danger("App.cs", source)
    ] == [("SKY-D212", 6), ("SKY-D216", 12)]


@pytest.mark.parametrize(
    ("field", "call", "expected"),
    [
        ("IUserRepository _repo;", "_repo.GetAsync(url)", []),
        ("HttpClient _repo;", "_repo.GetAsync(url)", [("SKY-D216", "CRITICAL")]),
        (
            "IHttpClientFactory _f;",
            'var client = _f.CreateClient("x"); client.PostAsync(url, null)',
            [("SKY-D216", "CRITICAL")],
        ),
        ("HttpClient _http;", '_http.GetAsync("https://api.example.com/i/" + url)', []),
        ("HttpClient _http;", '_http.GetAsync($"api/items/{url}")', []),
        (
            "HttpClient _http;",
            '_http.GetAsync("https://" + url)',
            [("SKY-D216", "CRITICAL")],
        ),
        ("HttpClient _http;", '_http.GetAsync("/" + url)', [("SKY-D216", "CRITICAL")]),
    ],
)
def test_ssrf_needs_an_http_client_receiver_and_an_open_host(field, call, expected):
    source = (
        f"public class ProxyController : Controller {{ private readonly {field} "
        f"public async Task Fetch(string url) {{ {call}; }} }}"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("return LocalRedirect(u);", []),
        ("return LocalRedirectPermanent(u);", []),
        ('if (Url.IsLocalUrl(u)) { return Redirect(u); } return Redirect("/");', []),
        ("if (!Url.IsLocalUrl(u)) { return BadRequest(); } return Redirect(u);", []),
        ('return Url.IsLocalUrl(u) ? Redirect(u) : Redirect("/");', []),
        ('return Redirect("/orders/" + u);', []),
        ("return Redirect(u);", [("SKY-D230", "HIGH")]),
        (
            "if (Url.IsLocalUrl(other)) { return Redirect(u); } return Ok();",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (Url.IsLocalUrl(u)) { return Ok(); } else { return Redirect(u); }",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (Url.IsLocalUrl(u) || other != null) return Redirect(u); return Ok();",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (!Url.IsLocalUrl(u)) { Log(u); } return Redirect(u);",
            [("SKY-D230", "HIGH")],
        ),
        ('return Redirect("/" + u);', [("SKY-D230", "HIGH")]),
        ("return new RedirectResult(u);", [("SKY-D230", "HIGH")]),
    ],
)
def test_open_redirect_respects_local_redirect_and_dominating_is_local_url(
    body, expected
):
    source = (
        "public class SessionController : Controller { "
        f"public IActionResult Go(string u, string other) {{ {body} }} }}"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            "if (Url.IsLocalUrl(u) == false) return Redirect(u); return Ok();",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (Url.IsLocalUrl(u) is false) return Redirect(u); return Ok();",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (!Url.IsLocalUrl(u)) { if (other == null) return Ok(); } "
            "return Redirect(u);",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (!Url.IsLocalUrl(u)) { if (other == null) return Ok(); else Log(u); } "
            "return Redirect(u);",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (other != null) { if (!Url.IsLocalUrl(u)) return Ok(); } "
            "return Redirect(u);",
            [("SKY-D230", "HIGH")],
        ),
        (
            "if (other != null) { Log(u); } else if (!Url.IsLocalUrl(u)) { return Ok(); } "
            "return Redirect(u);",
            [("SKY-D230", "HIGH")],
        ),
        (
            "return other != null || Url.IsLocalUrl(u) ? Redirect(u) : Ok();",
            [("SKY-D230", "HIGH")],
        ),
        ("if (Url.IsLocalUrl(u) == true) return Redirect(u); return Ok();", []),
        ("if (Url.IsLocalUrl(u) is false) return Ok(); return Redirect(u);", []),
        (
            "if (!Url.IsLocalUrl(u)) { if (other == null) throw new ArgumentException(); "
            "else return Ok(); } return Redirect(u);",
            [],
        ),
        ("return Url.IsLocalUrl(u) == false ? Ok() : Redirect(u);", []),
    ],
)
def test_is_local_url_guards_only_the_path_where_it_returned_true(body, expected):
    source = (
        "public class SessionController : Controller { "
        f"public IActionResult Go(string u, string other) {{ {body} }} }}"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("member", "check", "expected"),
    [
        (
            "private bool IsLocalUrl(string value) { return true; }",
            "IsLocalUrl(u)",
            [("SKY-D230", "HIGH")],
        ),
        (
            "private readonly UrlRules _rules;",
            "_rules.IsLocalUrl(u)",
            [("SKY-D230", "HIGH")],
        ),
        ("", "UrlRules.IsLocalUrl(u)", [("SKY-D230", "HIGH")]),
        (
            "public string Url { get; set; }",
            "Url.IsLocalUrl(u)",
            [("SKY-D230", "HIGH")],
        ),
        ("", "this.Url.IsLocalUrl(u)", []),
        ("private readonly IUrlHelper _urls;", "_urls.IsLocalUrl(u)", []),
    ],
)
def test_only_the_framework_url_helper_proves_a_redirect_local(member, check, expected):
    source = (
        "public static class UrlRules { public static bool IsLocalUrl(string v) "
        "{ return true; } } "
        f"public class SessionController : Controller {{ {member} "
        f"public IActionResult Go(string u) {{ if ({check}) return Redirect(u); "
        "return Ok(); } }"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            'Response.ContentType = "text/html"; '
            'if (plain) Response.ContentType = "text/plain"; Response.Write(html);',
            [("SKY-D228", "HIGH")],
        ),
        (
            'if (plain) Response.ContentType = "text/plain"; Response.Write(html);',
            [("SKY-D228", "HIGH")],
        ),
        (
            'Response.ContentType = "text/plain"; foreach (var line in html.Split(",")) '
            '{ Response.Write(line); Response.ContentType = "text/html"; }',
            [("SKY-D228", "HIGH")],
        ),
        ('Response.ContentType = "text/plain"; Response.Write(html);', []),
        (
            'if (plain) { Response.ContentType = "application/json"; } '
            'else { Response.ContentType = "text/plain"; } Response.Write(html);',
            [],
        ),
        (
            'if (plain) { Response.ContentType = "text/plain"; Response.Write(html); }',
            [],
        ),
    ],
)
def test_response_write_is_quiet_only_when_every_path_set_a_non_html_type(
    body, expected
):
    source = (
        "public class ViewController : Controller { [ValidateInput(false)] "
        f"public void Render(string html, bool plain) {{ {body} }} }}"
    )

    assert _rules(source) == expected


def test_redirect_in_a_non_controller_helper_fed_from_the_request_is_reported():
    source = (
        "public class Forwarder { public void Forward(HttpContext context) { "
        'var next = context.Request.Query["next"].ToString(); '
        "context.Response.Redirect(next); } }"
    )

    assert _rules(source) == [("SKY-D230", "HIGH")]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "public class ImportController : Controller { public object Load() { "
            "var f = new BinaryFormatter(); return f.Deserialize(Request.Body); } }",
            [("SKY-D233", "CRITICAL")],
        ),
        (
            "public class Cache { public object Load(string path) { "
            "using var s = File.OpenRead(path); "
            "return new BinaryFormatter().Deserialize(s); } }",
            [("SKY-D233", "HIGH")],
        ),
        (
            "public class ImportController : Controller { public object Load(Stream s) { "
            "IFormatter f = new SoapFormatter(); return f.Deserialize(s); } }",
            [("SKY-D233", "CRITICAL")],
        ),
        (
            "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };",
            [("SKY-D233", "HIGH")],
        ),
        (
            "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };",
            [],
        ),
        (
            "var s = new JsonSerializerSettings { TypeNameHandling = "
            "TypeNameHandling.Auto, SerializationBinder = new KnownTypes() };",
            [("SKY-D233", "MEDIUM")],
        ),
        (
            "var j = new JavaScriptSerializer(new SimpleTypeResolver());",
            [("SKY-D233", "HIGH")],
        ),
        ("var j = new JavaScriptSerializer();", []),
        (
            "public class ImportController : Controller { public object Load(string b) { "
            "return JsonSerializer.Deserialize<Order>(b); } }",
            [],
        ),
    ],
)
def test_unsafe_deserialization(source, expected):
    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (
            '_db.Orders.FromSqlRaw("SELECT * FROM o WHERE n = \'" + name + "\'");',
            [("SKY-D211", "CRITICAL")],
        ),
        (
            "_db.Orders.FromSqlRaw($\"SELECT * FROM o WHERE n = '{name}'\");",
            [("SKY-D211", "CRITICAL")],
        ),
        ('_db.Orders.FromSqlInterpolated($"SELECT * FROM o WHERE n = {name}");', []),
        ('_db.Orders.FromSqlRaw("SELECT * FROM o WHERE n = {0}", name);', []),
        (
            '_conn.Query<Order>("SELECT * FROM o WHERE n = \'" + name + "\'");',
            [("SKY-D211", "CRITICAL")],
        ),
        ('_conn.Query<Order>("SELECT * FROM o WHERE n = @n", new { n = name });', []),
        ('_other.Query("SELECT * FROM o WHERE n = \'" + name + "\'");', []),
        ('new SqlCommand("SELECT * FROM o WHERE id = " + id, _sql);', []),
    ],
)
def test_sql_injection_from_request_data(statement, expected):
    source = (
        "public class OrdersController : Controller { private readonly ShopContext _db; "
        "private readonly IDbConnection _conn; private readonly Search _other; "
        "private readonly SqlConnection _sql; "
        f"public void Find(string name, int id) {{ {statement} }} }}"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            'var sql = "SELECT * FROM o WHERE c = \'" + customer + "\'"; '
            "new SqlCommand(sql, _conn);",
            [("SKY-D211", "HIGH")],
        ),
        ("new SqlCommand(customer, _conn);", []),
    ],
)
def test_sql_text_built_from_a_service_parameter_is_reported_as_high(body, expected):
    source = (
        "public class OrderStore { private readonly SqlConnection _conn; "
        f"public void Find(string customer) {{ {body} }} }}"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("ViewBag.Bio = new HtmlString(bio);", [("SKY-D226", "HIGH")]),
        ("ViewBag.Bio = new HtmlString(HtmlEncoder.Default.Encode(bio));", []),
        ('return Content("<p>" + bio + "</p>", "text/html");', [("SKY-D228", "HIGH")]),
        ("return Content(bio);", []),
    ],
)
def test_request_data_marked_as_trusted_html(statement, expected):
    source = (
        "public class ProfileController : Controller { "
        f"public IActionResult Bio(string bio) {{ {statement} return View(); }} }}"
    )

    assert _rules(source) == expected


@pytest.mark.parametrize(
    ("directory", "expected"),
    [
        ("_uploads", []),
        ('_env.WebRootPath, "docs"', []),
        ("Directory.GetCurrentDirectory()", [("SKY-D215", "HIGH")]),
        ('"."', [("SKY-D215", "HIGH")]),
        ("name", [("SKY-D215", "HIGH")]),
    ],
)
def test_basename_containment_needs_a_directory_other_than_the_app_root(
    directory, expected
):
    source = (
        "public class FilesController : Controller { private readonly string _uploads; "
        "public string Read(string name) { return File.ReadAllText("
        f"Path.Combine({directory}, Path.GetFileName(name))); }} }}"
    )

    assert _rules(source) == expected


def test_csharp_security_findings_carry_the_catalog_cwe_on_the_sink_line():
    source = (
        "public class AccountController : Controller {\n"
        "  public object Restore(Stream body, string next) {\n"
        "    var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n"
        "    var target =\n"
        "      next;\n"
        "    if (target != null)\n"
        "      return Redirect(target);\n"
        "    return new BinaryFormatter().Deserialize(body);\n"
        "  }\n"
        "}\n"
    )

    findings = scan_danger("App.cs", source)

    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D233", 3),
        ("SKY-D230", 7),
        ("SKY-D233", 8),
    ]
    assert [[entry["id"] for entry in finding["cwe"]] for finding in findings] == [
        list(_SECURITY_RULE_CWES[finding["rule_id"]]) for finding in findings
    ]
    assert {entry["id"] for finding in findings for entry in finding["cwe"]} == {
        "CWE-502",
        "CWE-601",
    }
