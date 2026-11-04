from __future__ import annotations

import pytest

from skylos.visitors.languages.csharp.danger import scan_danger


_FAKE_CONTEXT = (
    "namespace Fake.Web { public class HttpContext { "
    "public static HttpContext Current { get; } = new HttpContext(); "
    "public ResponseDocument Response { get; } = new ResponseDocument(); } "
    "public class ResponseDocument { public string ContentType { get; set; } } }"
)


def _check(source, rule, unsafe):
    findings = scan_danger("App.cs", source)
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "// sink" in text)
    assert [(f["rule_id"], f["severity"], f["line"]) for f in findings] == (
        [(rule, "HIGH", line)] if unsafe else []
    )


@pytest.mark.parametrize(
    ("prefix", "member", "body", "unsafe"),
    [
        (
            "class UrlHelper { public bool IsLocalUrl(string s) => true; }",
            "",
            "var h = new UrlHelper();",
            True,
        ),
        (
            "class IUrlHelper { public bool IsLocalUrl(string s) => true; }",
            "",
            "var h = new IUrlHelper();",
            True,
        ),
        (
            "using UrlHelper = Fake; class Fake { public bool IsLocalUrl(string s) => true; }",
            "",
            "UrlHelper h = new Fake();",
            True,
        ),
        (
            "namespace Other { class UrlHelper { public bool IsLocalUrl(string s) => true; } }",
            "",
            "var h = new Other.UrlHelper();",
            True,
        ),
        (
            "class Fake { public bool IsLocalUrl(string s) => true; } "
            "class Factory { public Fake GetUrlHelper() => new Fake(); }",
            "",
            "var factory = new Factory(); var h = factory.GetUrlHelper();",
            True,
        ),
        (
            "class IUrlHelperFactory { public Fake GetUrlHelper() => new Fake(); } "
            "class Fake { public bool IsLocalUrl(string s) => true; }",
            "private IUrlHelperFactory factory;",
            "var h = factory.GetUrlHelper();",
            True,
        ),
        (
            "",
            "private IUrlHelperFactory factory;",
            "var h = factory.GetUrlHelper(ControllerContext);",
            False,
        ),
        (
            "namespace System.Web.Mvc { class UrlHelper { "
            "public bool IsLocalUrl(string s) => true; } }",
            "",
            "var h = new global::System.Web.Mvc.UrlHelper();",
            True,
        ),
        (
            "using Factory = Microsoft.AspNetCore.Mvc.Routing.IUrlHelperFactory;",
            "private Factory factory;",
            "var h = factory.GetUrlHelper(ControllerContext);",
            False,
        ),
        (
            "using Helper = Microsoft.AspNetCore.Mvc.IUrlHelper;",
            "private Helper h;",
            "",
            False,
        ),
        (
            "using Mvc = Microsoft.AspNetCore.Mvc;",
            "private Mvc.IUrlHelper h;",
            "",
            False,
        ),
        (
            "class UrlHelper { public bool IsLocalUrl(string s) => true; }",
            "",
            "var h = new global::System.Web.Mvc.UrlHelper(Request.RequestContext);",
            False,
        ),
        ("", "", "var h = Url; var copy = h; h = copy;", False),
    ],
)
def test_url_helper_proof_resolves_the_provider(prefix, member, body, unsafe):
    source = f"""{prefix}
public class SessionController : Controller {{
 {member}
 public ActionResult Go(string next) {{
  {body}
  if (h.IsLocalUrl(next)) return Redirect(next); // sink
  return Redirect("/");
 }}
}}
"""
    _check(source, "SKY-D230", unsafe)


@pytest.mark.parametrize(
    ("body", "check", "unsafe"),
    [
        ("var Url = new Fake();", "Url", True),
        ("var Url = new Fake();", "this.Url", False),
        ("var Url = new Fake();", "base.Url", False),
        ("dynamic h = new Fake(); if (flag) h = this.Url;", "h", True),
        ("dynamic h = this.Url; if (flag) h = new Fake();", "h", True),
    ],
)
def test_url_helper_shadowing_does_not_retroactively_prove_a_guard(body, check, unsafe):
    source = f"""class Fake {{ public bool IsLocalUrl(string s) => true; }}
public class SessionController : Controller {{
 public ActionResult Go(string next, bool flag) {{
  {body}
  if ({check}.IsLocalUrl(next)) return Redirect(next); // sink
  return Redirect("/");
 }}
}}
"""
    _check(source, "SKY-D230", unsafe)


@pytest.mark.parametrize(
    ("body", "sink", "unsafe"),
    [
        ('var doc = new Document(); doc.ContentType = "text/plain";', "Response", True),
        ('string ContentType; ContentType = "text/plain";', "Response", True),
        ('var doc = new Document { ContentType = "text/plain" };', "Response", True),
        ('this.Response.ContentType = "text/plain";', "this.Response", False),
        ('base.Response.ContentType = "text/plain";', "base.Response", False),
        (
            'var response = Response; response.ContentType = "text/plain";',
            "Response",
            False,
        ),
        (
            'var response = Response; var alias = response; alias.ContentType = "text/plain";',
            "Response",
            False,
        ),
        (
            'var response = Response; response.ContentType = "text/html";',
            "Response",
            True,
        ),
        (
            'var Response = new Document(); Response.ContentType = "text/plain";',
            "this.Response",
            True,
        ),
        (
            'var Response = new Document(); this.Response.ContentType = "text/plain";',
            "this.Response",
            False,
        ),
        (
            "dynamic response = Response; if (flag) response = new Document(); "
            'response.ContentType = "text/plain";',
            "Response",
            True,
        ),
        ('HttpContext.Response.ContentType = "text/plain";', "Response", False),
        (
            'System.Web.HttpContext.Current.Response.ContentType = "text/plain";',
            "Response",
            False,
        ),
        (
            'global::System.Web.HttpContext.Current.Response.ContentType = "text/plain";',
            "Response",
            False,
        ),
    ],
)
def test_response_type_proof_targets_the_actual_response(body, sink, unsafe):
    source = f"""class Document {{ public string ContentType {{ get; set; }} }}
public class ViewController : Controller {{
 [ValidateInput(false)]
 public void Render(string html, bool flag) {{
  this.Response.ContentType = "text/html";
  {body}
  {sink}.Write(html); // sink
 }}
}}
"""
    _check(source, "SKY-D228", unsafe)


@pytest.mark.parametrize(
    ("prefix", "receiver", "unsafe"),
    [
        ("using Web = System.Web;", "Web.HttpContext.Current.Response", False),
        (
            "using System = Fake; " + _FAKE_CONTEXT,
            "System.Web.HttpContext.Current.Response",
            True,
        ),
        (
            "using System = Fake; " + _FAKE_CONTEXT,
            "global::System.Web.HttpContext.Current.Response",
            False,
        ),
    ],
)
def test_response_qualification_resolves_namespace_aliases(prefix, receiver, unsafe):
    source = f"""{prefix}
public class ViewController : Controller {{
 [ValidateInput(false)]
 public void Render(string html) {{
  Response.ContentType = "text/html";
  {receiver}.ContentType = "text/plain";
  Response.Write(html); // sink
 }}
}}
"""
    _check(source, "SKY-D228", unsafe)


@pytest.mark.parametrize("receiver,unsafe", [("context", False), ("other", True)])
def test_response_proof_does_not_cross_context_instances(receiver, unsafe):
    source = f"""public class ViewController : Controller {{
 [ValidateInput(false)]
 public void Render(string html, HttpContext context, HttpContext other) {{
  context.Response.ContentType = "text/html";
  {receiver}.Response.ContentType = "text/plain";
  context.Response.Write(html); // sink
 }}
}}
"""
    _check(source, "SKY-D228", unsafe)
