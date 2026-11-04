from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze, proc_file
from skylos.visitors.languages.kotlin import scan_kotlin_file


def _scan_kotlin(tmp_path: Path, code: str, filename: str = "src/main/App.kt") -> tuple:
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_kotlin_file(str(file_path), {})


def test_kotlin_scanner_collects_defs_refs_and_raw_imports(tmp_path):
    defs, refs, _, _, visitor, _, quality, danger, _, _, _, _, raw_imports = (
        _scan_kotlin(
            tmp_path,
            """
package demo

import com.acme.Service
import com.acme.Legacy as OldService

class Controller {
    fun publicApi() {
        privateUsed()
    }

    private fun privateUsed() {}
    private fun privateDead() {}
}

fun main() {
    Controller().publicApi()
    topUsed()
}

private fun topUsed() {}
private fun topDead() {}
""",
        )
    )

    def_names = {definition.name for definition in defs}
    ref_names = {ref[0] for ref in refs}
    exported = {definition.name for definition in defs if definition.is_exported}

    assert "Service" in def_names
    assert "OldService" in def_names
    assert "Controller" in def_names
    assert "Controller.publicApi" in def_names
    assert "Controller.privateUsed" in def_names
    assert "Controller.privateDead" in def_names
    assert "main" in def_names
    assert "topUsed" in def_names
    assert "topDead" in def_names

    assert "Controller" in ref_names
    assert "publicApi" in ref_names
    assert "privateUsed" in ref_names
    assert "topUsed" in ref_names

    assert "Controller" in exported
    assert "Controller.publicApi" in exported
    assert "main" in exported
    assert "Controller.privateDead" not in exported
    assert "topDead" not in exported

    assert visitor.is_test_file is False
    assert quality == []
    assert danger == []
    assert raw_imports == [
        {"source": "com.acme.Service", "names": ["Service"], "line": 4},
        {"source": "com.acme.Legacy", "names": ["OldService"], "line": 5},
    ]


def test_kotlin_test_annotation_marks_function_as_test_entrypoint(tmp_path):
    defs, refs, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_kotlin(
        tmp_path,
        """
import kotlin.test.Test

class ControllerTest {
    @Test
    fun loadsUser() {}
}
""",
        filename="src/test/ControllerTest.kt",
    )

    test_method = next(definition for definition in defs if _is_loads_user(definition))

    assert test_method.is_exported is True
    assert visitor.is_test_file is True
    assert visitor.test_decorated_lines == {test_method.line}
    assert ("Test", str(tmp_path / "src/test/ControllerTest.kt")) in refs


def test_proc_file_dispatches_kotlin_to_kotlin_scanner(tmp_path):
    file_path = tmp_path / "Main.kt"
    file_path.write_text("fun main() {}\n", encoding="utf-8")

    out = proc_file(str(file_path))
    defs = out[0]

    assert any(definition.name == "main" for definition in defs)


def test_analyze_kotlin_reports_language_summary_and_dead_code(tmp_path):
    file_path = tmp_path / "Main.kt"
    file_path.write_text(
        """
fun main() {
    used()
}

private fun used() {}
private fun unusedPrivate() {}
""",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {item["full_name"] for item in result["unused_functions"]}

    assert result["analysis_summary"]["languages"] == {"Kotlin": 1}
    assert "unusedPrivate" in unused
    assert "used" not in unused


def _is_loads_user(definition) -> bool:
    return definition.name == "ControllerTest.loadsUser"


def test_kotlin_references_outside_calls_keep_private_symbols_and_imports_live(
    tmp_path,
):
    (tmp_path / "Uses.kt").write_text(
        """
package demo

import javax.servlet.http.HttpServletRequest
import java.time.Instant
import java.util.UUID
import java.io.IOException
import java.util.Base64
import java.util.Objects
import androidx.compose.runtime.getValue
import java.time.ZoneId
import java.time.Clock
import com.acme.settings.timeout
import java.time.Duration
import java.time.Duration.ofSeconds

class Uses {
    fun handle(request: HttpServletRequest): Instant? = null
    fun check(value: Any) = value is UUID
    fun load(): String {
        try {
            return "ok"
        } catch (e: IOException) {
            return "fail"
        }
    }
    fun run(items: List<String>): Int {
        val sizes = items.map(::measure)
        retrying { note() }
        val joined = items.joinToString(separator = ",")
        return sizes.size + (3 combine 4) + joined.length + Remote.call(timeout = 1)
    }
    fun banner(title: String) = "${title.shout()} ${Base64.getEncoder()}"
    fun wait() = ofSeconds(1)

    // ZoneId is chosen by the caller.
    fun label() = "Clock"

    /** Same as [Objects.equals]. */
    fun same(a: Any?, b: Any?) = a == b

    private fun measure(text: String) = text.length
    private fun retrying(block: () -> Unit) = block()
    private fun note() = Unit
    private infix fun Int.combine(other: Int) = this * 10 + other
    private fun String.shout() = uppercase()
    private fun separator() = ","
    private fun neverUsed() = Unit
}

private class TypeOnly
private class Orphan

class Holder {
    private var value: TypeOnly? = null
    fun describe() = "Orphan"
}
""",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {
        item["name"]
        for key in ("unused_functions", "unused_imports", "unused_classes")
        for item in result[key]
    }

    assert unused == {
        "ZoneId",
        "Clock",
        "timeout",
        "Duration",
        "Uses.separator",
        "Uses.neverUsed",
        "Orphan",
    }
    imports = {item["name"]: item["line"] for item in result["unused_imports"]}
    assert imports["ZoneId"] == 11


_SPRING = """
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*

@RestController
class Api(private val jdbcTemplate: JdbcTemplate) {
    @GetMapping("/x")
    fun handle(@RequestParam q: String, @RequestParam n: Int): Any {
        BODY
    }
}
"""

_KTOR = """
import io.ktor.server.application.*
import io.ktor.server.routing.*

fun Application.module(client: io.ktor.client.HttpClient) {
    routing {
        get("/x") {
            BODY
        }
    }
}
"""

_SERVLET = """
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class Page {
    fun handle(req: HttpServletRequest, resp: HttpServletResponse) {
        BODY
    }
}
"""

_SINK_CASES = [
    (
        _SPRING,
        "return jdbcTemplate.queryForList(\"SELECT * FROM t WHERE a = '$q'\") // SINK",
        "SKY-D211",
        "CRITICAL",
    ),
    (
        _SPRING,
        'return jdbcTemplate.queryForList("SELECT * FROM t WHERE a = ?", q) // SINK',
        "SKY-D211",
        None,
    ),
    (
        _SPRING,
        'return jdbcTemplate.queryForList("SELECT * FROM t WHERE a = $n") // SINK',
        "SKY-D211",
        None,
    ),
    (_SPRING, 'return searchIndex.query("name:$q") // SINK', "SKY-D211", None),
    (_SPRING, 'return java.io.File("/srv", q).readText() // SINK', "SKY-D215", "HIGH"),
    (
        _SPRING,
        'if (!q.startsWith("docs/")) throw Exception()\n        return java.io.File("/srv", q).readText() // SINK',
        "SKY-D215",
        "HIGH",
    ),
    (
        _SPRING,
        'val base = java.io.File("/srv").canonicalFile\n        val f = java.io.File(base, q).canonicalFile // SINK\n        if (!f.toPath().startsWith(base.toPath())) throw Exception()\n        return f.readText()',
        "SKY-D215",
        None,
    ),
    (
        _SPRING,
        'return java.io.File("/srv", java.io.File(q).name).readText() // SINK',
        "SKY-D215",
        None,
    ),
    (_SPRING, 'return "redirect:$q" // SINK', "SKY-D230", "HIGH"),
    (_SPRING, 'return "redirect:/items/$q" // SINK', "SKY-D230", None),
    (
        _SPRING,
        'if (q !in setOf("/a")) return "redirect:/"\n        return "redirect:$q" // SINK',
        "SKY-D230",
        None,
    ),
    (_SPRING, "return java.net.URL(q).readText() // SINK", "SKY-D216", "CRITICAL"),
    (
        _SPRING,
        'return java.net.URL("https://api.example.com/v1/$q").readText() // SINK',
        "SKY-D216",
        None,
    ),
    (
        _SPRING,
        'return ProcessBuilder("sh", "-c", "ls $q").start() // SINK',
        "SKY-D212",
        "CRITICAL",
    ),
    (
        _SPRING,
        'return ProcessBuilder("head", "-n", q.toInt().toString()).start() // SINK',
        "SKY-D212",
        None,
    ),
    (
        _SPRING,
        "return org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression(q).value // SINK",
        "SKY-D237",
        "CRITICAL",
    ),
    (
        _SPRING,
        'val text = "Runtime.getRuntime().exec(q)" // SINK\n        return text',
        "SKY-D212",
        None,
    ),
    (
        _KTOR,
        'val id = call.parameters["id"]\n            java.sql.DriverManager.getConnection("x").createStatement().executeQuery("SELECT * FROM t WHERE id = \'$id\'") // SINK',
        "SKY-D211",
        "CRITICAL",
    ),
    (
        _KTOR,
        'val name = call.receiveText()\n            java.io.File("/data/$name").writeText("x") // SINK',
        "SKY-D215",
        "HIGH",
    ),
    (
        _KTOR,
        'val n = call.parameters["n"]?.toIntOrNull() ?: 0\n            java.io.File("/data/$n.txt").readText() // SINK',
        "SKY-D215",
        None,
    ),
    (
        _KTOR,
        'call.parameters["f"]?.let { name ->\n                java.io.File("/data", name).delete() // SINK\n            }',
        "SKY-D215",
        "HIGH",
    ),
    (
        _KTOR,
        'val target = call.request.queryParameters["u"]!!\n            client.get(target) // SINK',
        "SKY-D216",
        "CRITICAL",
    ),
    (
        _KTOR,
        'val target = call.request.queryParameters["u"]!!\n            client.get("https://api.example.com/v1/$target") // SINK',
        "SKY-D216",
        None,
    ),
    (
        _KTOR,
        'call.respondRedirect(call.request.queryParameters["next"]!!) // SINK',
        "SKY-D230",
        "HIGH",
    ),
    (
        _KTOR,
        'val who = call.parameters["who"]\n            call.respondText("<p>$who</p>", ContentType.Text.Html) // SINK',
        "SKY-D226",
        "HIGH",
    ),
    (
        _KTOR,
        'val who = call.parameters["who"]\n            call.respondText("Hello $who") // SINK',
        "SKY-D226",
        None,
    ),
    (
        _SERVLET,
        'Runtime.getRuntime().exec(req.getParameter("cmd")) // SINK',
        "SKY-D212",
        "CRITICAL",
    ),
    (
        _SERVLET,
        'Runtime.getRuntime().exec(arrayOf("ls", "-la")) // SINK',
        "SKY-D203",
        "LOW",
    ),
    (
        _SERVLET,
        'resp.writer.write("<b>" + req.queryString + "</b>") // SINK',
        "SKY-D226",
        "HIGH",
    ),
    (
        _SERVLET,
        'resp.writer.write(org.owasp.encoder.Encode.forHtml(req.getParameter("q"))) // SINK',
        "SKY-D226",
        None,
    ),
    (
        _SERVLET,
        "java.io.ObjectInputStream(req.inputStream).readObject() // SINK",
        "SKY-D204",
        "CRITICAL",
    ),
    (
        _SERVLET,
        "val f = javax.xml.parsers.DocumentBuilderFactory.newInstance()\n        f.newDocumentBuilder().parse(req.inputStream) // SINK",
        "SKY-D236",
        "CRITICAL",
    ),
    (
        _SERVLET,
        'val f = javax.xml.parsers.DocumentBuilderFactory.newInstance()\n        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)\n        f.newDocumentBuilder().parse(req.inputStream) // SINK',
        "SKY-D236",
        None,
    ),
    (
        _SERVLET,
        'val hardened = javax.xml.parsers.DocumentBuilderFactory.newInstance()\n        hardened.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)\n        val open = javax.xml.parsers.DocumentBuilderFactory.newInstance()\n        open.newDocumentBuilder().parse(req.inputStream) // SINK',
        "SKY-D236",
        "CRITICAL",
    ),
]


def _findings_on_sink_line(tmp_path, code, rule_id):
    danger = _scan_kotlin(tmp_path, code)[7]
    sink_line = next(
        number
        for number, line in enumerate(code.splitlines(), start=1)
        if "// SINK" in line
    )
    return [
        finding["severity"]
        for finding in danger
        if finding["rule_id"] == rule_id and finding["line"] == sink_line
    ]


_ESCAPE_IMPORT = "import org.apache.commons.text.StringEscapeUtils.escapeHtml4"
_FAKE_ESCAPE = "fun escapeHtml4(value: String): String = value"


@pytest.mark.parametrize(
    "prelude, member, body, severity",
    [
        (
            _ESCAPE_IMPORT,
            "",
            'resp.writer.write("<a href=\'" + escapeHtml4(q) + "\'>x</a>") // SINK',
            "HIGH",
        ),
        (
            _ESCAPE_IMPORT,
            "",
            "resp.writer.write(\"<a href='${escapeHtml4(q)}'>x</a>\") // SINK",
            "HIGH",
        ),
        (
            _ESCAPE_IMPORT,
            "",
            'val label = escapeHtml4(q)\n        resp.writer.write("<form action=\'" + label + "\'>") // SINK',
            "HIGH",
        ),
        (
            "import org.owasp.encoder.Encode",
            "",
            'resp.writer.write("<input value=\\"" + Encode.forHtmlContent(q) + "\\">") // SINK',
            "HIGH",
        ),
        (
            _ESCAPE_IMPORT,
            "",
            'resp.writer.write("<p>" + escapeHtml4(q) + "</p>") // SINK',
            None,
        ),
        (
            _ESCAPE_IMPORT,
            "",
            'resp.writer.write("<a href=\'https://example.com/" + escapeHtml4(q) + "\'>x</a>") // SINK',
            None,
        ),
        (
            _FAKE_ESCAPE,
            "",
            "resp.writer.write(escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            _ESCAPE_IMPORT,
            _FAKE_ESCAPE,
            "resp.writer.write(escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "object StringEscapeUtils {\n    " + _FAKE_ESCAPE + "\n}",
            "",
            "resp.writer.write(StringEscapeUtils.escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "",
            "",
            "resp.writer.write(escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "import org.apache.commons.text.StringEscapeUtils as Escapes",
            "",
            "resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            None,
        ),
    ],
)
def test_kotlin_html_encoder_counts_only_for_its_context_and_real_library(
    tmp_path, prelude, member, body, severity
):
    code = (
        "import javax.servlet.http.HttpServletRequest\n"
        "import javax.servlet.http.HttpServletResponse\n"
        f"{prelude}\n\n"
        "class Page {\n"
        f"    {member}\n"
        "    fun handle(req: HttpServletRequest, resp: HttpServletResponse) {\n"
        '        val q = req.getParameter("q")\n'
        f"        {body}\n"
        "    }\n"
        "}\n"
    )
    hits = _findings_on_sink_line(tmp_path, code, "SKY-D226")

    if severity is None:
        assert hits == []
    else:
        assert hits == [severity]


@pytest.mark.parametrize(
    "prelude, declaration, body, severity",
    [
        (
            "",
            "Escapes: Fake, ",
            "resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "",
            "",
            "val Escapes = Fake()\n        resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "",
            "",
            "val (Escapes, unused) = Pair(Fake(), 0)\n        resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "",
            "",
            "listOf(Fake()).forEach { Escapes ->\n            resp.writer.write(Escapes.escapeHtml4(q)) // SINK\n        }",
            "HIGH",
        ),
        (
            "",
            "",
            "run {\n            val Escapes = Fake()\n            resp.writer.write(Escapes.escapeHtml4(q)) // SINK\n        }",
            "HIGH",
        ),
        (
            "",
            "",
            "listOf(Fake()).forEach { Escapes: Fake ->\n            resp.writer.write(Escapes.escapeHtml4(q)) // SINK\n        }",
            "HIGH",
        ),
        (
            "",
            "",
            "for (Escapes in listOf(Fake())) {\n            resp.writer.write(Escapes.escapeHtml4(q)) // SINK\n        }",
            "HIGH",
        ),
        (
            "",
            "",
            "run { val Escapes = Fake() }\n        resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            None,
        ),
        (
            "",
            "",
            "resp.writer.write(Escapes.escapeHtml4(q)) // SINK\n        val Escapes = Fake()",
            None,
        ),
        (
            "fun unrelated(Escapes: Fake) = Escapes\n",
            "",
            "resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            None,
        ),
        (
            "class Unrelated(val Escapes: Fake)\n",
            "",
            "resp.writer.write(Escapes.escapeHtml4(q)) // SINK",
            None,
        ),
    ],
)
def test_kotlin_encoder_import_does_not_override_a_local_binding(
    tmp_path, prelude, declaration, body, severity
):
    code = (
        "import javax.servlet.http.HttpServletRequest\n"
        "import javax.servlet.http.HttpServletResponse\n"
        "import org.apache.commons.text.StringEscapeUtils as Escapes\n"
        "class Fake { fun escapeHtml4(value: String): String = value }\n"
        f"{prelude}"
        f"fun render({declaration}req: HttpServletRequest, resp: HttpServletResponse) {{\n"
        '    val q = req.getParameter("q")\n'
        f"    {body}\n"
        "}\n"
    )
    hits = _findings_on_sink_line(tmp_path, code, "SKY-D226")
    assert hits == ([] if severity is None else [severity])


@pytest.mark.parametrize(
    "member, parameter, body",
    [
        ("val Escapes = Fake()", "", "Escapes.escapeHtml4(q)"),
        ("", "val Escapes: Fake, ", "Escapes.escapeHtml4(q)"),
        ("val escapeHtml4: (String) -> String = { it }", "", "escapeHtml4(q)"),
        (
            "",
            "",
            "run { val escapeHtml4: (String) -> String = { it }; escapeHtml4(q) }",
        ),
    ],
)
def test_kotlin_encoder_import_does_not_override_a_member_or_function_value(
    tmp_path, member, parameter, body
):
    code = (
        "import javax.servlet.http.HttpServletRequest\n"
        "import javax.servlet.http.HttpServletResponse\n"
        "import org.apache.commons.text.StringEscapeUtils as Escapes\n"
        "import org.apache.commons.text.StringEscapeUtils.escapeHtml4\n"
        "class Fake { fun escapeHtml4(value: String): String = value }\n"
        f"class Page({parameter}val ignored: Int = 0) {{\n"
        "    fun render(req: HttpServletRequest, resp: HttpServletResponse) {\n"
        '        val q = req.getParameter("q")\n'
        f"        resp.writer.write({body}) // SINK\n"
        "    }\n"
        f"    {member}\n"
        "}\n"
    )
    assert _findings_on_sink_line(tmp_path, code, "SKY-D226") == ["HIGH"]


@pytest.mark.parametrize(
    "parameter, body, severity",
    [
        (
            "escapeHtml4: (String) -> String, ",
            "resp.writer.write(escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "",
            "val escapeHtml4: (String) -> String = { it }\n    resp.writer.write(escapeHtml4(q)) // SINK",
            "HIGH",
        ),
        (
            "",
            "run { val escapeHtml4: (String) -> String = { it } }\n    resp.writer.write(escapeHtml4(q)) // SINK",
            None,
        ),
        ("", "resp.writer.write(escapeHtml4(q)) // SINK", None),
    ],
)
def test_kotlin_imported_encoder_function_can_be_shadowed_by_a_value(
    tmp_path, parameter, body, severity
):
    code = (
        "import javax.servlet.http.HttpServletRequest\n"
        "import javax.servlet.http.HttpServletResponse\n"
        "import org.apache.commons.text.StringEscapeUtils.escapeHtml4\n"
        f"fun render({parameter}req: HttpServletRequest, resp: HttpServletResponse) {{\n"
        '    val q = req.getParameter("q")\n'
        f"    {body}\n"
        "}\n"
    )
    assert _findings_on_sink_line(tmp_path, code, "SKY-D226") == (
        [] if severity is None else [severity]
    )


@pytest.mark.parametrize(
    "parameter, setup, severity",
    [
        ("encoder: Encoder, ", "", None),
        ("", "val encoder = ESAPI.encoder()", None),
        ("", "val encoder: Encoder = ESAPI.encoder()", None),
        ("encoder: Fake, ", "", "HIGH"),
    ],
)
def test_kotlin_esapi_encoder_receiver_requires_the_real_type(
    tmp_path, parameter, setup, severity
):
    code = (
        "import javax.servlet.http.HttpServletRequest\n"
        "import javax.servlet.http.HttpServletResponse\n"
        "import org.owasp.esapi.ESAPI\n"
        "import org.owasp.esapi.Encoder\n"
        "class Fake { fun encodeForHTML(value: String): String = value }\n"
        f"fun render({parameter}req: HttpServletRequest, resp: HttpServletResponse) {{\n"
        '    val q = req.getParameter("q")\n'
        f"    {setup}\n"
        "    resp.writer.write(encoder.encodeForHTML(q)) // SINK\n"
        "}\n"
    )
    assert _findings_on_sink_line(tmp_path, code, "SKY-D226") == (
        [] if severity is None else [severity]
    )


@pytest.mark.parametrize("template, body, rule_id, severity", _SINK_CASES)
def test_kotlin_request_data_reaches_security_sinks(
    tmp_path, template, body, rule_id, severity
):
    hits = _findings_on_sink_line(tmp_path, template.replace("BODY", body), rule_id)

    if severity is None:
        assert hits == []
    else:
        assert hits == [severity]


@pytest.mark.parametrize(
    "body, rule_id, severity",
    [
        (
            'webView.settings.javaScriptEnabled = true\n        webView.addJavascriptInterface(Any(), "bridge") // SINK',
            "SKY-D257",
            "HIGH",
        ),
        (
            'webView.settings.javaScriptEnabled = false\n        webView.addJavascriptInterface(Any(), "bridge") // SINK',
            "SKY-D257",
            None,
        ),
        (
            "webView.settings.allowUniversalAccessFromFileURLs = true // SINK",
            "SKY-D258",
            "MEDIUM",
        ),
        (
            "webView.settings.setAllowFileAccessFromFileURLs(true) // SINK",
            "SKY-D258",
            "MEDIUM",
        ),
        (
            "webView.settings.allowFileAccessFromFileURLs = false // SINK",
            "SKY-D258",
            None,
        ),
    ],
)
def test_kotlin_android_webview_settings(tmp_path, body, rule_id, severity):
    code = (
        "import android.webkit.WebView\n\n"
        "class Browser(private val webView: WebView) {\n"
        "    fun configure() {\n"
        f"        {body}\n"
        "    }\n"
        "}\n"
    )
    hits = _findings_on_sink_line(tmp_path, code, rule_id)

    if severity is None:
        assert hits == []
    else:
        assert hits == [severity]
