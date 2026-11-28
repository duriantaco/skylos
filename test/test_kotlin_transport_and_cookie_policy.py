from textwrap import dedent

from skylos.visitors.languages.kotlin import scan_kotlin_file


def _findings(tmp_path, source, rule):
    path = tmp_path / "App.kt"
    path.write_text(dedent(source), encoding="utf-8")
    return [
        (finding["rule_id"], finding["line"], finding.get("cwe"))
        for finding in scan_kotlin_file(str(path), {})[7]
        if finding["rule_id"] == rule
    ]


def test_cipher_mode_requires_a_resolved_jca_factory(tmp_path):
    assert _findings(
        tmp_path,
        """\
        import javax.crypto.Cipher as JcaCipher
        import javax.crypto.Cipher.getInstance as createCipher
        val configured = JcaCipher.getInstance("AES/ECB/NoPadding")
        fun values(local: LocalCipher, JcaCipher: LocalCipher) {
            JcaCipher.getInstance("AES/ECB/NoPadding")
            local.getInstance("AES/ECB/NoPadding")
            createCipher("AES/ecb/PKCS5Padding")
            javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
            javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            javax.crypto.Cipher.getInstance("AES")
            javax.crypto.Cipher.getInstance("AES/OTHER/ECB")
            javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        }
        class LocalCipher {
            fun getInstance(mode: String) = mode
        }
        """,
        "SKY-D384",
    ) == [
        ("SKY-D384", 3, "CWE-327"),
        ("SKY-D384", 7, "CWE-327"),
        ("SKY-D384", 8, "CWE-327"),
    ]


def test_sensitive_servlet_cookie_flags_at_dispatch(tmp_path):
    assert _findings(
        tmp_path,
        """\
        import jakarta.servlet.http.Cookie as ServletCookie
        import jakarta.servlet.http.HttpServletResponse as Response
        fun write(response: Response, token: String, condition: Boolean) {
            val session = ServletCookie("session_id", token)
            session.setSecure(true)
            response.addCookie(session)
            val signed = ServletCookie("access_token", token)
            signed.secure = true
            signed.isHttpOnly = true
            response.addCookie(signed)
            val expired = ServletCookie("session", "")
            response.addCookie(expired)
            response.addCookie(jakarta.servlet.http.Cookie("refresh_token", token))
            response.addCookie(ServletCookie("display_theme", "dark"))
            val prepared = ServletCookie("session", token)
            if (condition) { prepare(prepared) }
            response.addCookie(prepared)
        }
        """,
        "SKY-D252",
    ) == [("SKY-D252", 6, "CWE-1004"), ("SKY-D252", 13, "CWE-614")]


def test_sensitive_ktor_flags_require_application_call_owner(tmp_path):
    assert _findings(
        tmp_path,
        """\
        import io.ktor.server.application.ApplicationCall as KtorCall
        fun write(call: KtorCall, local: LocalCall, token: String) {
            call.response.cookies.append("session", token, httpOnly = true)
            call.response.cookies.append(name = "session", value = token, secure = true, httpOnly = true)
            call.response.cookies.append(name = "sid", value = token, secure = true, httpOnly = false)
            call.response.cookies.append("csrf_token", token, secure = true)
            call.response.cookies.append("session", "", maxAge = 0)
            local.response.cookies.append("session", token)
        }
        """,
        "SKY-D252",
    ) == [("SKY-D252", 3, "CWE-614"), ("SKY-D252", 5, "CWE-1004")]
