from __future__ import annotations

from pathlib import Path

import pytest

from skylos.visitors.languages.java.core import JavaCore
from skylos.visitors.languages.java.flow import (
    MAX_CONSTANT_STRING_CHARS,
    MAX_CONSTANT_STORE_CHARS,
    JavaFlowState,
    JavaSecurityFlowAnalyzer,
    scan_java_security_flows,
)
from skylos.visitors.languages.java import scan_java_file


def _scan_java(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "App.java"
    file_path.write_text(code, encoding="utf-8")
    return scan_java_file(str(file_path), {})[7]


def _scan_java_primary_flow(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "App.java"
    source = code.encode("utf-8")
    file_path.write_bytes(source)
    core = JavaCore(str(file_path), source)
    core.scan()
    return scan_java_security_flows(core.root_node, str(file_path), source)


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def _categories(findings: list[dict]) -> set[str]:
    return {finding.get("category", "") for finding in findings}


def test_java_constant_folding_caps_string_concatenation():
    analyzer = JavaSecurityFlowAnalyzer(None, "App.java", b"")

    allowed = analyzer._eval_binary("A" * (MAX_CONSTANT_STRING_CHARS - 1), "+", "B")
    assert isinstance(allowed, str)
    assert len(allowed) == MAX_CONSTANT_STRING_CHARS

    assert analyzer._eval_binary("A" * MAX_CONSTANT_STRING_CHARS, "+", "B") is None


def test_java_constant_store_has_total_string_budget():
    analyzer = JavaSecurityFlowAnalyzer(None, "App.java", b"")
    state = JavaFlowState()
    chunk = "A" * MAX_CONSTANT_STRING_CHARS

    for index in range(MAX_CONSTANT_STORE_CHARS // MAX_CONSTANT_STRING_CHARS):
        analyzer._store_constant(f"s{index}", chunk, state)

    assert sum(
        len(value) for value in state.constants.values() if isinstance(value, str)
    ) == MAX_CONSTANT_STORE_CHARS

    analyzer._store_constant("too_much", chunk, state)

    assert "too_much" not in state.constants
    assert sum(
        len(value) for value in state.constants.values() if isinstance(value, str)
    ) <= MAX_CONSTANT_STORE_CHARS


def test_object_input_stream_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;

class App {
  Object read(InputStream in) throws Exception {
    ObjectInputStream stream = new ObjectInputStream(in);
    return stream.readObject();
  }
}
""",
    )
    assert "SKY-D204" in _rule_ids(findings)


def test_java_base64_alphabet_constant_is_not_secret(tmp_path):
    findings = _scan_java(
        tmp_path,
        """class App {
  private static final String C64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
}
""",
    )
    assert "SKY-S101" not in _rule_ids(findings)


def test_zip_slip_style_archive_extraction_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, String destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      File out = new File(destDir, entry.getName());
      FileOutputStream fos = new FileOutputStream(out);
    }
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_archive_extraction_with_normalize_guard_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, Path destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      Path target = destDir.resolve(entry.getName()).normalize();
      if (!target.startsWith(destDir)) {
        throw new IOException("bad zip");
      }
      Files.copy(zis, target);
    }
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_archive_extraction_with_canonical_guard_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, File destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      File file = new File(destDir, entry.getName());
      if (!file.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {
        throw new IOException("bad zip");
      }
      FileOutputStream fos = new FileOutputStream(file);
    }
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_archive_extraction_canonical_string_prefix_without_separator_still_flags(
    tmp_path,
):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, File destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      File file = new File(destDir, entry.getName());
      String targetPath = file.getCanonicalPath();
      String basePath = destDir.getCanonicalPath();
      if (!targetPath.startsWith(basePath)) {
        throw new IOException("bad zip");
      }
      FileOutputStream fos = new FileOutputStream(file);
    }
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_archive_extraction_canonical_string_prefix_with_separator_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, File destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      File file = new File(destDir, entry.getName());
      String targetPath = file.getCanonicalPath();
      String basePath = destDir.getCanonicalPath() + File.separator;
      if (!targetPath.startsWith(basePath)) {
        throw new IOException("bad zip");
      }
      FileOutputStream fos = new FileOutputStream(file);
    }
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_archive_extraction_unrelated_canonical_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, File destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      File file = new File(destDir, entry.getName());
      String targetPath = file.getCanonicalPath();
      String otherPath = new File("/tmp/other").getCanonicalPath();
      String otherBase = new File("/tmp/base").getCanonicalPath() + File.separator;
      if (!otherPath.startsWith(otherBase)) {
        throw new IOException("bad unrelated path");
      }
      FileOutputStream fos = new FileOutputStream(file);
    }
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_archive_extraction_mixed_safe_and_unsafe_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

class App {
  void unzip(ZipInputStream zis, Path destDir) throws Exception {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
      Path safeTarget = destDir.resolve(entry.getName()).normalize();
      if (!safeTarget.startsWith(destDir)) {
        throw new IOException("bad zip");
      }
      Files.copy(zis, safeTarget);

      File unsafeFile = new File(destDir.toFile(), entry.getName());
      FileOutputStream fos = new FileOutputStream(unsafeFile);
    }
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_servlet_request_path_traversal_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    String file = request.getParameter("file");
    Path target = Paths.get("/srv/data", file);
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_inline_request_path_traversal_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path target = Paths.get("/srv/data", request.getParameter("file"));
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_multiline_request_path_traversal_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    String file = request.getParameter("file");
    Path target = Paths.get("/srv/data", file);
    return Files.readString(
      target
    );
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_multiline_request_source_assignment_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    String file = request.getParameter(
      "file"
    );
    return Files.readString(Paths.get("/srv/data", file));
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_request_path_with_normalize_guard_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String file = request.getParameter("file");
    Path target = base.resolve(file).normalize();
    if (!target.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_request_path_canonical_string_prefix_without_separator_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    File base = new File("/srv/data");
    File target = new File(base, request.getParameter("file"));
    String targetPath = target.getCanonicalPath();
    String basePath = base.getCanonicalPath();
    if (!targetPath.startsWith(basePath)) {
      throw new IllegalArgumentException("bad path");
    }
    return new BufferedReader(new FileReader(target)).readLine();
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_request_path_canonical_string_prefix_with_separator_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    File base = new File("/srv/data");
    File target = new File(base, request.getParameter("file"));
    String targetPath = target.getCanonicalPath();
    String basePath = base.getCanonicalPath() + File.separator;
    if (!targetPath.startsWith(basePath)) {
      throw new IllegalArgumentException("bad path");
    }
    return new BufferedReader(new FileReader(target)).readLine();
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_request_path_unrelated_canonical_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    File base = new File("/srv/data");
    File target = new File(base, request.getParameter("file"));
    String targetPath = target.getCanonicalPath();
    String otherPath = new File("/tmp/other").getCanonicalPath();
    String otherBase = new File("/tmp/base").getCanonicalPath() + File.separator;
    if (!otherPath.startsWith(otherBase)) {
      throw new IllegalArgumentException("bad unrelated path");
    }
    return new BufferedReader(new FileReader(target)).readLine();
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_request_path_normalize_and_startswith_noop_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String file = request.getParameter("file");
    Path target = base.resolve(file);
    target = target.normalize();
    target.startsWith(base);
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_request_path_mixed_safe_and_unsafe_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String safeName = request.getParameter("safe");
    Path safe = base.resolve(safeName).normalize();
    if (!safe.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }

    String file = request.getParameter("file");
    Path target = Paths.get("/srv/data", file);
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_reassigned_guarded_request_path_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String file = request.getParameter("file");
    Path target = base.resolve(file).normalize();
    if (!target.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }

    target = Paths.get("/tmp", request.getParameter("other"));
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_spring_request_param_path_traversal_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import org.springframework.web.bind.annotation.RequestParam;

class App {
  byte[] download(@RequestParam String name) throws Exception {
    Path target = Path.of("/srv/data", name);
    return Files.readAllBytes(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_multipart_upload_copy_is_not_flagged_as_path_traversal(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

class App {
  void upload(HttpServletRequest request) throws Exception {
    Part upload = request.getPart("file");
    Path target = Paths.get("/srv/data", "upload.bin");
    Files.copy(upload.getInputStream(), target);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_tainted_content_written_to_fixed_path_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import org.springframework.web.bind.annotation.RequestParam;

class App {
  void write(@RequestParam String name) throws Exception {
    Path target = Paths.get("/srv/data", "log.txt");
    Files.writeString(target, name);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_rewritten_request_path_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String file = request.getParameter("file");
    file = "ok.txt";
    return Files.readString(base.resolve(file));
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_non_request_receiver_is_not_treated_as_request_source(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;

class Meta {
  String getHeader(String name) { return name; }
}

class App {
  String read(Meta meta) throws Exception {
    String file = meta.getHeader("file");
    return Files.readString(Paths.get("/srv/data", file));
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_final_request_assignment_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    final String file = request.getParameter("file");
    Path target = Paths.get("/srv/data", file);
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_positive_startswith_guard_inside_branch_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String file = request.getParameter("file");
    Path target = base.resolve(file).normalize();
    if (target.startsWith(base)) {
      return Files.readString(target);
    }
    throw new IllegalArgumentException("bad path");
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_braceless_positive_startswith_guard_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    Path base = Paths.get("/srv/data");
    String file = request.getParameter("file");
    Path target = base.resolve(file).normalize();
    if (target.startsWith(base))
      return Files.readString(target);
    throw new IllegalArgumentException("bad path");
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_insecure_cookie_secure_false_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void issue(HttpServletResponse response) {
    Cookie cookie = new Cookie("sid", "value");
    cookie.setSecure(false);
    cookie.setHttpOnly(true);
    response.addCookie(cookie);
  }
}
""",
    )
    assert "SKY-D252" in _rule_ids(findings)


def test_secure_cookie_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void issue(HttpServletResponse response) {
    Cookie cookie = new Cookie("sid", "value");
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
    response.addCookie(cookie);
  }
}
""",
    )
    assert "SKY-D252" not in _rule_ids(findings)


def test_java_random_remember_me_cookie_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void issue(HttpServletRequest request, HttpServletResponse response) {
    String token = Long.toString(new java.util.Random().nextLong());
    Cookie rememberMe = new Cookie("rememberMe", token);
    rememberMe.setSecure(true);
    request.getSession().setAttribute("rememberMe", token);
    response.addCookie(rememberMe);
  }
}
""",
    )
    assert "SKY-D250" in _rule_ids(findings)


def test_secure_random_remember_me_cookie_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void issue(HttpServletRequest request, HttpServletResponse response) {
    java.security.SecureRandom random = new java.security.SecureRandom();
    String token = Long.toString(random.nextLong());
    Cookie rememberMe = new Cookie("rememberMe", token);
    rememberMe.setSecure(true);
    request.getSession().setAttribute("rememberMe", token);
    response.addCookie(rememberMe);
  }
}
""",
    )
    assert "SKY-D250" not in _rule_ids(findings)


def test_process_builder_command_list_with_tainted_shell_string_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String param = request.getHeader("cmd");
    List<String> args = new ArrayList<String>();
    args.add("sh");
    args.add("-c");
    args.add("echo " + param);
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(args);
    pb.start();
  }
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_process_builder_constant_command_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String param = request.getHeader("cmd");
    List<String> args = new ArrayList<String>();
    args.add("sh");
    args.add("-c");
    args.add("echo safe");
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(args);
    pb.start();
  }
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_tainted_sql_variable_prepare_call_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, java.sql.Connection connection) throws Exception {
    String param = request.getParameter("proc");
    String sql = "{call " + param + "}";
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    statement.executeQuery();
  }
}
""",
    )
    assert "SKY-D211" in _rule_ids(findings)


def test_parameterized_sql_constant_query_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, java.sql.Connection connection) throws Exception {
    String param = request.getParameter("id");
    java.sql.PreparedStatement statement = connection.prepareStatement(
        "select * from users where id = ?"
    );
    statement.setString(1, param);
    statement.executeQuery();
  }
}
""",
    )
    assert "SKY-D211" not in _rule_ids(findings)


def test_tainted_ldap_filter_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, javax.naming.directory.InitialDirContext ctx) throws Exception {
    String param = request.getHeader("uid");
    String filter = "(uid=" + param + ")";
    ctx.search("ou=users", filter, new javax.naming.directory.SearchControls());
  }
}
""",
    )
    assert "ldap_injection" in _categories(findings)


def test_tainted_xpath_expression_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, javax.xml.xpath.XPath xpath, Object doc) throws Exception {
    String param = request.getParameter("path");
    String expression = "/users/user[name='" + param + "']";
    xpath.evaluate(expression, doc);
  }
}
""",
    )
    assert "xpath_injection" in _categories(findings)


def test_java_url_openstream_tainted_request_flags_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    new URL(target).openStream();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_url_constructor_without_network_use_is_not_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.*;
import javax.servlet.http.*;

class App {
  String run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URL url = new URL(target);
    return url.toString();
  }
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_java_http_request_builder_tainted_uri_flags_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_uri_chain_tainted_uri_flags_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    return HttpRequest.newBuilder().uri(URI.create(target)).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_variable_uri_tainted_uri_flags_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    HttpRequest.Builder builder = HttpRequest.newBuilder();
    return builder.uri(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_split_declaration_flags_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    HttpRequest.Builder builder;
    builder = HttpRequest.newBuilder();
    return builder.uri(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_host_allowlist_guard_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    if (!"api.example.com".equals(uri.getHost())) {
      throw new IllegalArgumentException("bad host");
    }
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_java_http_request_builder_host_allowlist_with_benign_else_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    if (!"api.example.com".equals(uri.getHost())) {
      throw new IllegalArgumentException("bad host");
    } else {
      System.out.println("allowed");
    }
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_java_http_request_builder_partial_host_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request, boolean debug) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    if (!"api.example.com".equals(uri.getHost()) && debug) {
      throw new IllegalArgumentException("bad host");
    }
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_else_reassignment_after_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    if (!"api.example.com".equals(uri.getHost())) {
      throw new IllegalArgumentException("bad host");
    } else {
      uri = URI.create(request.getParameter("next"));
    }
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_weak_host_contains_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    if (!uri.getHost().contains(".")) {
      throw new IllegalArgumentException("bad host");
    }
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_http_request_builder_unrelated_host_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.net.URI;
import java.net.http.HttpRequest;
import javax.servlet.http.*;

class App {
  HttpRequest run(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    URI checked = URI.create("https://api.example.com/users");
    if (!"api.example.com".equals(checked.getHost())) {
      throw new IllegalArgumentException("bad host");
    }
    return HttpRequest.newBuilder(uri).build();
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_rest_template_tainted_url_flags_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;

class App {
  Object run(HttpServletRequest request) {
    String target = request.getParameter("url");
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(target, String.class);
  }
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_java_rest_template_method_name_without_receiver_type_is_not_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class Exchange {
  Object exchange(String value) { return value; }
}

class App {
  Object run(HttpServletRequest request) {
    String target = request.getParameter("url");
    Exchange exchange = new Exchange();
    return exchange.exchange(target);
  }
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_java_rest_template_known_non_rest_template_receiver_is_not_ssrf(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class FakeClient {
  Object getForObject(String value, Class<?> type) { return value; }
}

class App {
  Object run(HttpServletRequest request) {
    String target = request.getParameter("url");
    FakeClient restTemplate = new FakeClient();
    return restTemplate.getForObject(target, String.class);
  }
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_java_send_redirect_tainted_target_flags_open_redirect(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    response.sendRedirect(next);
  }
}
""",
    )
    assert "SKY-D230" in _rule_ids(findings)


def test_java_send_redirect_relative_guard_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    if (!next.startsWith("/") || next.startsWith("//")) {
      throw new IllegalArgumentException("bad redirect");
    }
    response.sendRedirect(next);
  }
}
""",
    )
    assert "SKY-D230" not in _rule_ids(findings)


def test_java_send_redirect_relative_guard_with_benign_else_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    if (!next.startsWith("/") || next.startsWith("//")) {
      throw new IllegalArgumentException("bad redirect");
    } else {
      System.out.println("allowed");
    }
    response.sendRedirect(next);
  }
}
""",
    )
    assert "SKY-D230" not in _rule_ids(findings)


def test_java_send_redirect_partial_relative_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response, boolean debug) throws Exception {
    String next = request.getParameter("next");
    if (debug && (!next.startsWith("/") || next.startsWith("//"))) {
      throw new IllegalArgumentException("bad redirect");
    }
    response.sendRedirect(next);
  }
}
""",
    )
    assert "SKY-D230" in _rule_ids(findings)


def test_java_send_redirect_else_reassignment_after_guard_still_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    if (!next.startsWith("/") || next.startsWith("//")) {
      throw new IllegalArgumentException("bad redirect");
    } else {
      next = request.getParameter("fallback");
    }
    response.sendRedirect(next);
  }
}
""",
    )
    assert "SKY-D230" in _rule_ids(findings)


def test_java_send_redirect_slash_guard_without_protocol_relative_check_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    if (!next.startsWith("/")) {
      throw new IllegalArgumentException("bad redirect");
    }
    response.sendRedirect(next);
  }
}
""",
    )
    assert "SKY-D230" in _rule_ids(findings)


def test_tainted_writer_output_flags_xss(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("name");
    response.getWriter().println(param);
  }
}
""",
    )
    assert "SKY-D226" in _rule_ids(findings)


def test_html_encoded_writer_output_is_not_flagged_xss(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("name");
    response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
  }
}
""",
    )
    assert "SKY-D226" not in _rule_ids(findings)


ISSUE_699_SOURCE = """final class Main {
  static void rememberTheme(Request request) {
    String theme = request.getParameter("theme");
    request.getSession().setAttribute("theme", theme);
  }
}

interface Request {
  String getParameter(String name);
  Session getSession();
}

interface Session {
  void setAttribute(String name, String value);
}
"""


def _assert_session_trust_boundary_identity(findings: list[dict]) -> None:
    matches = [
        finding
        for finding in findings
        if finding.get("category") == "trust_boundary"
    ]
    assert len(matches) == 1
    assert matches[0]["rule_id"] == "SKY-D254"
    assert matches[0]["severity"] == "HIGH"
    assert matches[0]["cwe"] == "CWE-501"
    assert "SKY-D253" not in _rule_ids(findings)


def test_tainted_session_attribute_has_distinct_rule_identity(tmp_path):
    findings = _scan_java_primary_flow(tmp_path, ISSUE_699_SOURCE)
    _assert_session_trust_boundary_identity(findings)


def test_tainted_session_attribute_integration_uses_distinct_rule_identity(tmp_path):
    findings = _scan_java(tmp_path, ISSUE_699_SOURCE)
    _assert_session_trust_boundary_identity(findings)


def test_tainted_session_attribute_fallback_has_same_rule_identity(
    tmp_path, monkeypatch
):
    def fail_primary_flow(*_args, **_kwargs):
        raise RuntimeError("force compatibility fallback")

    monkeypatch.setattr(
        "skylos.visitors.languages.java.danger.scan_java_security_flows",
        fail_primary_flow,
    )
    findings = _scan_java(
        tmp_path,
        ISSUE_699_SOURCE,
    )
    _assert_session_trust_boundary_identity(findings)


def test_constant_session_attribute_is_not_trust_boundary(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) {
    String param = request.getParameter("user");
    String safe = "fixed";
    request.getSession().setAttribute("userid", safe);
  }
}
""",
    )
    assert "trust_boundary" not in _categories(findings)
    assert "SKY-D254" not in _rule_ids(findings)


def test_cookie_value_path_traversal_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    Cookie[] cookies = request.getCookies();
    Cookie cookie = cookies[0];
    String file = cookie.getValue();
    FileInputStream stream = new FileInputStream(new File(file));
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_parameter_map_writer_output_flags_xss(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Map<String, String[]> map = request.getParameterMap();
    String param = "";
    if (!map.isEmpty()) {
      String[] values = map.get("name");
      if (values != null) param = values[0];
    }
    response.getWriter().printf(param, "x");
  }
}
""",
    )
    assert "SKY-D226" in _rule_ids(findings)


def test_map_get_tainted_value_flags_command_and_safe_key_is_safe(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String param = request.getHeader("cmd");
    HashMap<String, Object> values = new HashMap<String, Object>();
    values.put("safe", "echo ok");
    values.put("user", param);
    String command = (String) values.get("user");
    Runtime.getRuntime().exec("sh -c " + command);
  }
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)

    safe_findings = _scan_java(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String param = request.getHeader("cmd");
    HashMap<String, Object> values = new HashMap<String, Object>();
    values.put("safe", "echo ok");
    values.put("user", param);
    String command = (String) values.get("safe");
    Runtime.getRuntime().exec("sh -c " + command);
  }
}
""",
    )
    assert "SKY-D212" not in _rule_ids(safe_findings)


def test_list_remove_then_tainted_get_flags_xss(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("name");
    List<String> values = new ArrayList<String>();
    values.add("safe");
    values.add(param);
    values.remove(0);
    String rendered = values.get(0);
    response.getWriter().format(rendered, "x");
  }
}
""",
    )
    assert "SKY-D226" in _rule_ids(findings)


def test_separate_class_get_the_parameter_path_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class RequestCarrier {
  private HttpServletRequest request;
  RequestCarrier(HttpServletRequest request) { this.request = request; }
  String readParameter(String name) { return request.getParameter(name); }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    RequestCarrier carrier = new RequestCarrier(request);
    String file = carrier.readParameter("file");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_helper_method_name_alone_is_not_treated_as_request_source(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class RequestCarrier {
  RequestCarrier(HttpServletRequest request) {}
  String getTheParameter(String name) { return name; }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    RequestCarrier carrier = new RequestCarrier(request);
    String file = carrier.getTheParameter("file");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_request_backed_no_arg_safe_helper_is_not_tainted_by_name(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class RequestCarrier {
  RequestCarrier(HttpServletRequest request) {}
  String getPath() { return "fixed.txt"; }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    RequestCarrier carrier = new RequestCarrier(request);
    String file = carrier.getPath();
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_helper_summary_is_class_aware_for_same_method_name(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class UnsafeCarrier {
  private HttpServletRequest request;
  UnsafeCarrier(HttpServletRequest request) { this.request = request; }
  String readParameter(String name) { return request.getParameter(name); }
}

class SafeCarrier {
  SafeCarrier(HttpServletRequest request) {}
  String readParameter(String name) { return "fixed.txt"; }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    SafeCarrier carrier = new SafeCarrier(request);
    String file = carrier.readParameter("file");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_helper_summary_is_overload_aware(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class Carrier {
  private HttpServletRequest request;
  Carrier(HttpServletRequest request) { this.request = request; }
  String getPath() { return request.getParameter("file"); }
  String getPath(String ignored) { return "fixed.txt"; }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    Carrier carrier = new Carrier(request);
    String file = carrier.getPath("ignored");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_static_safe_branch_from_wrapper_source_is_not_flagged(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class SeparateClassRequest {
  SeparateClassRequest(HttpServletRequest request) {}
  String getTheParameter(String name) { return name; }
}

class App {
  void run(HttpServletRequest request) {
    SeparateClassRequest scr = new SeparateClassRequest(request);
    String param = scr.getTheParameter("user");
    int num = 106;
    String key = (7 * 18) + num > 200 ? "fixed" : param;
    request.getSession().setAttribute(key, "value");
  }
}
""",
    )
    assert "trust_boundary" not in _categories(findings)


def test_spring_jdbc_query_for_object_tainted_sql_flags(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) {
    String param = request.getParameter("password");
    String sql = "select id from users where password='" + param + "'";
    Object result = DatabaseHelper.JDBCtemplate.queryForObject(
        sql, Object.class
    );
  }
}
""",
    )
    assert "SKY-D211" in _rule_ids(findings)


def test_primary_java_flow_handles_core_security_without_fallback(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.*;

class App {
  String run(HttpServletRequest request, HttpServletResponse response, java.sql.Connection connection) throws Exception {
    String name = request.getHeader("name");
    response.getWriter().println(name);

    String table = request.getParameter("table");
    String sql = "select * from " + table;
    connection.prepareStatement(sql);

    Path base = Paths.get("/srv/data");
    Path target = base.resolve(request.getParameter("file")).normalize();
    if (!target.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D226" in _rule_ids(findings)
    assert "SKY-D211" in _rule_ids(findings)
    assert "SKY-D215" not in _rule_ids(findings)


def test_primary_java_flow_helper_summary_is_class_and_arity_aware(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class UnsafeCarrier {
  private HttpServletRequest request;
  UnsafeCarrier(HttpServletRequest request) { this.request = request; }
  String readParameter(String name) { return request.getParameter(name); }
}

class SafeCarrier {
  SafeCarrier(HttpServletRequest request) {}
  String readParameter(String name) { return "fixed.txt"; }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    SafeCarrier carrier = new SafeCarrier(request);
    String file = carrier.readParameter("file");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)

    unsafe_findings = _scan_java_primary_flow(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class UnsafeCarrier {
  private HttpServletRequest request;
  UnsafeCarrier(HttpServletRequest request) { this.request = request; }
  String readParameter(String name) { return request.getParameter(name); }
}

class App {
  void run(HttpServletRequest request) throws Exception {
    UnsafeCarrier carrier = new UnsafeCarrier(request);
    String file = carrier.readParameter("file");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(unsafe_findings)


def test_primary_java_flow_path_guard_requires_dominating_exit(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.*;

class App {
  String read(HttpServletRequest request, boolean debug) throws Exception {
    Path base = Paths.get("/srv/data");
    Path target = base.resolve(request.getParameter("file")).normalize();
    if (!target.startsWith(base)) {
      if (debug) return "debug";
    }
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_primary_java_flow_path_guard_rejects_partial_boolean_guard(tmp_path):
    negative_findings = _scan_java_primary_flow(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.*;

class App {
  String read(HttpServletRequest request, boolean allowUnsafe) throws Exception {
    Path base = Paths.get("/srv/data");
    Path target = base.resolve(request.getParameter("file")).normalize();
    if (!target.startsWith(base) && allowUnsafe) {
      throw new IllegalArgumentException("bad path");
    }
    return Files.readString(target);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(negative_findings)

    positive_findings = _scan_java_primary_flow(
        tmp_path,
        """import java.nio.file.*;
import javax.servlet.http.*;

class App {
  String read(HttpServletRequest request, boolean allowUnsafe) throws Exception {
    Path base = Paths.get("/srv/data");
    Path target = base.resolve(request.getParameter("file")).normalize();
    if (target.startsWith(base) || allowUnsafe) {
      return Files.readString(target);
    }
    throw new IllegalArgumentException("bad path");
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(positive_findings)


def test_primary_java_flow_resolves_unqualified_same_class_helper(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class App {
  String read(HttpServletRequest request, String name) {
    return request.getParameter(name);
  }

  void run(HttpServletRequest request) throws Exception {
    String file = read(request, "file");
    File target = new File(file);
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_primary_java_flow_treats_cookie_values_as_request_tainted(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.io.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    Cookie[] cookies = request.getCookies();
    String file = "fallback.txt";
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        file = cookie.getValue();
        break;
      }
    }
    FileInputStream stream = new FileInputStream(new File(file));
  }
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_primary_java_flow_switch_taint_reaches_process_builder_list(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String param = request.getParameter("cmd");
    String command;
    switch (request.getParameter("mode")) {
      case "user":
        command = param;
        break;
      default:
        command = "echo safe";
        break;
    }
    List<String> args = new ArrayList<String>();
    args.add("sh");
    args.add("-c");
    args.add(command);
    ProcessBuilder pb = new ProcessBuilder(args);
    pb.start();
  }
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_primary_java_flow_constant_switch_uses_selected_branch(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import java.util.*;
import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) throws Exception {
    String param = request.getParameter("cmd");
    String command;
    String guess = "ABC";
    char switchTarget = guess.charAt(1);
    switch (switchTarget) {
      case 'A':
        command = param;
        break;
      case 'B':
        command = "echo safe";
        break;
      default:
        command = param;
        break;
    }
    List<String> args = new ArrayList<String>();
    args.add("sh");
    args.add("-c");
    args.add(command);
    ProcessBuilder pb = new ProcessBuilder(args);
    pb.start();
  }
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_primary_java_flow_request_backed_same_project_wrapper_accessors(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, javax.naming.directory.InitialDirContext ctx) throws Exception {
    SeparateClassRequest scr = new SeparateClassRequest(request);
    String param = scr.getTheParameter("uid");
    String filter = "(uid=" + param + ")";
    ctx.search("ou=users", filter, new javax.naming.directory.SearchControls());
  }
}

class SeparateClassRequest {
  private HttpServletRequest request;

  SeparateClassRequest(HttpServletRequest request) {
    this.request = request;
  }

  String getTheParameter(String name) {
    return request.getParameter(name);
  }
}
""",
    )
    assert "ldap_injection" in _categories(findings)


def test_primary_java_flow_unknown_external_wrapper_accessors_are_not_sources(tmp_path):
    findings = _scan_java_primary_flow(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, javax.naming.directory.InitialDirContext ctx) throws Exception {
    AuditContext audit = new AuditContext(request);
    String timeout = audit.getQueryTimeout();
    String prefix = audit.getPathPrefix();
    ctx.search("ou=users", timeout, new javax.naming.directory.SearchControls());
    java.io.FileInputStream stream = new java.io.FileInputStream(prefix);
  }
}
""",
    )
    assert "ldap_injection" not in _categories(findings)
    assert "SKY-D215" not in _rule_ids(findings)


def _findings_on(findings: list[dict], marker_line: int, rule_id: str) -> list[dict]:
    return [
        finding
        for finding in findings
        if finding["line"] == marker_line and finding["rule_id"] == rule_id
    ]


def _marked_line(code: str, marker: str = "// SINK") -> int:
    for index, line in enumerate(code.splitlines(), start=1):
        if marker in line:
            return index
    raise AssertionError("marker not found")


_SPRING_HEADER = """import java.net.URI;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import jakarta.persistence.EntityManager;

class UserDto {
  private String name;
  public String getName() { return name; }
}

interface UserService { void update(String name); }

@Controller
class App {
  private JdbcTemplate jdbcTemplate;
  private EntityManager entityManager;
  private RestTemplate restTemplate;
  private WebClient webClient;
  private UserService userService;

"""


@pytest.mark.parametrize(
    ("body", "rule_id", "severity"),
    [
        (
            """  @PostMapping("/a")
  Object a(@RequestBody UserDto dto) {
    return jdbcTemplate.queryForList("SELECT * FROM u WHERE n = '" + dto.getName() + "'"); // SINK
  }""",
            "SKY-D211",
            "CRITICAL",
        ),
        (
            """  @GetMapping("/b")
  Object b(String q) {
    return entityManager.createQuery("from User u where u.name = '" + q + "'"); // SINK
  }""",
            "SKY-D211",
            "CRITICAL",
        ),
        (
            """  @GetMapping("/p")
  Object p(@RequestParam String name) {
    StringBuilder sql = new StringBuilder("SELECT * FROM u");
    sql.append(" WHERE n = '").append(name).append("'");
    return jdbcTemplate.queryForList(sql.toString()); // SINK
  }""",
            "SKY-D211",
            "CRITICAL",
        ),
        (
            """  @GetMapping("/c")
  Object c(@RequestParam long id) {
    return jdbcTemplate.queryForList("SELECT * FROM u WHERE id = " + id); // SINK
  }""",
            "SKY-D211",
            None,
        ),
        (
            """  @GetMapping("/d")
  Object d(@RequestParam String name) {
    return jdbcTemplate.queryForList("SELECT * FROM u WHERE n = ?", name); // SINK
  }""",
            "SKY-D211",
            None,
        ),
        (
            """  @PostMapping("/e")
  void e(@RequestBody UserDto dto) {
    userService.update("name=" + dto.getName()); // SINK
  }""",
            "SKY-D211",
            None,
        ),
        (
            """  @GetMapping("/f")
  String f(@RequestParam String next) {
    return "redirect:" + next; // SINK
  }""",
            "SKY-D230",
            "HIGH",
        ),
        (
            """  @GetMapping("/g")
  String g(@RequestParam String next) {
    return "redirect:/" + next; // SINK
  }""",
            "SKY-D230",
            "HIGH",
        ),
        (
            """  @GetMapping("/h")
  String h(@PathVariable String ownerId) {
    return "redirect:/owners/" + ownerId; // SINK
  }""",
            "SKY-D230",
            None,
        ),
        (
            """  @GetMapping("/i")
  String i(@RequestParam String next) {
    if (!next.startsWith("/") || next.startsWith("//")) {
      return "redirect:/";
    }
    return "redirect:" + next; // SINK
  }""",
            "SKY-D230",
            None,
        ),
        (
            """  @GetMapping("/j")
  String j(@RequestParam String next) {
    String target = clean(next);
    return "redirect:" + target; // SINK
  }

  private String clean(String value) { return value.trim(); }""",
            "SKY-D230",
            "HIGH",
        ),
        (
            """  @GetMapping("/k")
  Object k(@RequestParam String next) {
    return org.springframework.http.ResponseEntity.status(302).location(URI.create(next)).build(); // SINK
  }""",
            "SKY-D230",
            "HIGH",
        ),
        (
            """  @GetMapping("/l")
  String l(@RequestParam String url) {
    return webClient.get().uri(url).retrieve().bodyToMono(String.class).block(); // SINK
  }""",
            "SKY-D216",
            "CRITICAL",
        ),
        (
            """  @GetMapping("/m")
  String m(@RequestParam String id) {
    return webClient.get().uri("/users/{id}", id).retrieve().bodyToMono(String.class).block(); // SINK
  }""",
            "SKY-D216",
            None,
        ),
        (
            """  @GetMapping("/n")
  String n(@RequestParam String id) {
    return restTemplate.getForObject("https://api.example.com/users/" + id, String.class); // SINK
  }""",
            "SKY-D216",
            None,
        ),
        (
            """  @GetMapping("/o")
  String o(@RequestParam String host) {
    return restTemplate.getForObject("https://" + host + "/status", String.class); // SINK
  }""",
            "SKY-D216",
            "CRITICAL",
        ),
    ],
)
def test_spring_sources_and_sinks(tmp_path, body, rule_id, severity):
    code = _SPRING_HEADER + body + "\n}\n"
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), rule_id)
    if severity is None:
        assert hits == []
    else:
        assert [finding["severity"] for finding in hits] == [severity]


def test_spring_mapping_outside_a_controller_does_not_bind_plain_params(tmp_path):
    code = """import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/plain")
class App {
  private JdbcTemplate jdbcTemplate;

  @GetMapping("/x")
  Object x(String q) {
    return jdbcTemplate.queryForList("SELECT * FROM t WHERE q = '" + q + "'"); // SINK
  }
}
"""
    findings = _scan_java(tmp_path, code)
    assert [f for f in findings if f.get("cwe") == "CWE-89"] == []


@pytest.mark.parametrize(
    ("statement", "rule_id", "severity"),
    [
        ("Runtime.getRuntime().exec(cmd); // SINK", "SKY-D212", "CRITICAL"),
        (
            'Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping " + cmd}); // SINK',
            "SKY-D212",
            "CRITICAL",
        ),
        (
            'new ProcessBuilder("sh", "-c", "dig " + cmd).start(); // SINK',
            "SKY-D212",
            "CRITICAL",
        ),
        (
            'new ProcessBuilder().command("sh", "-c", cmd).redirectErrorStream(true).start(); // SINK',
            "SKY-D212",
            "CRITICAL",
        ),
        ("Runtime.getRuntime().exec(local); // SINK", "SKY-D203", "HIGH"),
        ('Runtime.getRuntime().exec("uptime"); // SINK', "SKY-D203", "LOW"),
        ('new ProcessBuilder("uptime").start(); // SINK', "SKY-D212", None),
    ],
)
def test_runtime_exec_and_process_builder(tmp_path, statement, rule_id, severity):
    code = (
        "import javax.servlet.http.*;\n\nclass App {\n"
        "  void run(HttpServletRequest request, String local) throws Exception {\n"
        '    String cmd = request.getParameter("cmd");\n'
        f"    {statement}\n"
        "  }\n}\n"
    )
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), rule_id)
    if severity is None:
        assert hits == []
    else:
        assert [finding["severity"] for finding in hits] == [severity]
    if rule_id == "SKY-D203" and severity == "LOW":
        assert hits[0]["low_risk_context"]["reason"] == "constant-shell-command"


_XML_HEADER = """import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.*;

class App {
  private static final String DISALLOW = "http://apache.org/xml/features/disallow-doctype-decl";

  Object run(InputStream in, HttpServletRequest request, boolean strict, org.w3c.dom.Document doc) throws Exception {
"""


@pytest.mark.parametrize(
    ("body", "severity"),
    [
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            "HIGH",
        ),
        (
            """    return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getInputStream()); // SINK""",
            "CRITICAL",
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      dbf.setFeature(DISALLOW, true);
    } catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    }
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            None,
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            None,
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilderFactory other = DocumentBuilderFactory.newInstance();
    other.setFeature(DISALLOW, true);
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            "HIGH",
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            "HIGH",
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    dbf.setFeature(DISALLOW, true);
    return db.parse(in); // SINK""",
            "HIGH",
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    if (strict) {
      dbf.setFeature(DISALLOW, true);
    }
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            "HIGH",
        ),
        (
            """    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    return dbf.newDocumentBuilder().parse(in); // SINK""",
            "HIGH",
        ),
        (
            """    XMLInputFactory xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    return xif.createXMLStreamReader(in); // SINK""",
            None,
        ),
        (
            """    XMLInputFactory xif = XMLInputFactory.newInstance();
    return xif.createXMLStreamReader(in); // SINK""",
            "HIGH",
        ),
        (
            """    Transformer t = TransformerFactory.newInstance().newTransformer();
    t.transform(new DOMSource(doc), new StreamResult(System.out)); // SINK
    return null;""",
            None,
        ),
        (
            """    Transformer t = TransformerFactory.newInstance().newTransformer();
    t.transform(new StreamSource(in), new StreamResult(System.out)); // SINK
    return null;""",
            "HIGH",
        ),
        (
            """    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    return db.newDocument(); // SINK""",
            None,
        ),
    ],
)
def test_xml_parsers_report_xxe_unless_hardened_first(tmp_path, body, severity):
    code = _XML_HEADER + body + "\n  }\n}\n"
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), "SKY-D236")
    if severity is None:
        assert hits == []
    else:
        assert [finding["severity"] for finding in hits] == [severity]
        assert hits[0]["cwe"] == "CWE-611"


@pytest.mark.parametrize(
    ("imports", "body", "severity"),
    [
        (
            "import java.beans.XMLDecoder;",
            "return new XMLDecoder(request.getInputStream()).readObject(); // SINK",
            "CRITICAL",
        ),
        (
            "import org.yaml.snakeyaml.Yaml;",
            "return new Yaml().load(in); // SINK",
            "MEDIUM",
        ),
        (
            "import org.yaml.snakeyaml.*;\nimport org.yaml.snakeyaml.constructor.SafeConstructor;",
            "return new Yaml(new SafeConstructor(new LoaderOptions())).load(in); // SINK",
            None,
        ),
        (
            "import org.yaml.snakeyaml.Yaml;\nclass SafeConstructor extends org.yaml.snakeyaml.constructor.Constructor {}",
            "return new Yaml(new SafeConstructor()).load(in); // SINK",
            "MEDIUM",
        ),
        (
            "import com.thoughtworks.xstream.XStream;",
            "XStream x = new XStream();\n    return x.fromXML(request.getReader()); // SINK",
            "HIGH",
        ),
        (
            "import com.thoughtworks.xstream.XStream;\nimport com.thoughtworks.xstream.security.AnyTypePermission;",
            "XStream x = new XStream();\n    x.addPermission(AnyTypePermission.ANY);\n    return x.fromXML(request.getReader()); // SINK",
            "CRITICAL",
        ),
        (
            "import com.thoughtworks.xstream.XStream;\nimport com.thoughtworks.xstream.security.NoTypePermission;",
            "XStream x = new XStream();\n    x.addPermission(NoTypePermission.NONE);\n    return x.fromXML(in); // SINK",
            None,
        ),
        (
            "import com.fasterxml.jackson.databind.ObjectMapper;",
            "ObjectMapper m = new ObjectMapper();\n    m.enableDefaultTyping(); // SINK\n    return m;",
            "HIGH",
        ),
        (
            "import java.io.ObjectInputStream;",
            "return new ObjectInputStream(socket.getInputStream()).readObject(); // SINK",
            "CRITICAL",
        ),
        (
            "import java.io.ObjectInputStream;",
            'ObjectInputStream ois = new ObjectInputStream(in); // SINK\n    ois.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("app.*;!*"));\n    return ois.readObject();',
            "MEDIUM",
        ),
    ],
)
def test_unsafe_deserializers(tmp_path, imports, body, severity):
    code = (
        f"{imports}\nimport java.io.*;\nimport javax.servlet.http.*;\n\nclass App {{\n"
        "  Object run(HttpServletRequest request, InputStream in, java.net.Socket socket) throws Exception {\n"
        f"    {body}\n"
        "  }\n}\n"
    )
    line = _marked_line(code)
    hits = [
        finding
        for finding in _scan_java(tmp_path, code)
        if finding["line"] == line and finding["rule_id"] in {"SKY-D204", "SKY-D233"}
    ]
    if severity is None:
        assert hits == []
    else:
        assert [finding["severity"] for finding in hits] == [severity]


@pytest.mark.parametrize(
    ("statement", "rule_id"),
    [
        (
            "new org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression(value); // SINK",
            "SKY-D237",
        ),
        ("new javax.naming.InitialContext().lookup(value); // SINK", "SKY-D237"),
        (
            'new javax.script.ScriptEngineManager().getEngineByName("js").eval(value); // SINK',
            "SKY-D237",
        ),
        ("new groovy.lang.GroovyShell().evaluate(value); // SINK", "SKY-D237"),
        ('xpath.evaluate("/u[@n=\'" + value + "\']", doc); // SINK', "SKY-D229"),
        ('ctx.search("ou=people", "(uid=" + value + ")", null); // SINK', "SKY-D239"),
    ],
)
def test_expression_jndi_ldap_and_xpath_sinks(tmp_path, statement, rule_id):
    code = (
        "import javax.servlet.http.*;\n\nclass App {\n"
        "  void run(HttpServletRequest request, javax.xml.xpath.XPath xpath, Object doc, "
        "javax.naming.directory.DirContext ctx) throws Exception {\n"
        '    String value = request.getParameter("v");\n'
        f"    {statement}\n"
        "  }\n}\n"
    )
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), rule_id)
    assert [finding["severity"] for finding in hits] == ["CRITICAL"]


@pytest.mark.parametrize(
    "statement",
    [
        "java.util.regex.Pattern.compile(value); // SINK",
        'searchService.search("products", value); // SINK',
        "cache.lookup(value); // SINK",
        'new javax.naming.InitialContext().lookup("java:comp/env/jdbc/app"); // SINK',
        'new org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression("1 + 1"); // SINK',
    ],
)
def test_same_named_methods_on_other_receivers_are_not_injection_sinks(
    tmp_path, statement
):
    code = (
        "import javax.servlet.http.*;\n\n"
        "interface SearchService { Object search(String index, String term); }\n"
        "class Cache { Object lookup(String key) { return key; } }\n\n"
        "class App {\n"
        "  void run(HttpServletRequest request, SearchService searchService, Cache cache) throws Exception {\n"
        '    String value = request.getParameter("v");\n'
        f"    {statement}\n"
        "  }\n}\n"
    )
    line = _marked_line(code)
    assert [
        finding
        for finding in _scan_java(tmp_path, code)
        if finding["line"] == line
        and finding["rule_id"]
        in {"SKY-D229", "SKY-D237", "SKY-D239", "SKY-D240", "SKY-D241"}
    ] == []


def test_velocity_template_built_from_request_is_template_injection(tmp_path):
    code = """import javax.servlet.http.*;
import java.io.StringWriter;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

class App {
  void run(HttpServletRequest request) throws Exception {
    String template = request.getParameter("t");
    Velocity.evaluate(new VelocityContext(), new StringWriter(), "x", template); // SINK
  }
}
"""
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), "SKY-D349")
    assert [finding["severity"] for finding in hits] == ["CRITICAL"]


def test_taint_assigned_inside_catch_block_reaches_sql_sink(tmp_path):
    code = """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
    try {
      stmt.close();
    } catch (Exception e) {
      String q = request.getParameter("q");
      stmt.executeQuery(q); // SINK
    }
  }
}
"""
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), "SKY-D211")
    assert [finding["severity"] for finding in hits] == ["CRITICAL"]


@pytest.mark.parametrize(
    ("statement", "reported"),
    [
        (
            'ctx.search("ou=people", "(uid=" + LdapEncoder.filterEncode(uid) + ")", controls); // SINK',
            False,
        ),
        (
            'String safe = Rdn.escapeValue(uid);\n    ctx.search("ou=people", "(uid=" + safe + ")", controls); // SINK',
            False,
        ),
        (
            'ldapTemplate.search("", new EqualsFilter("uid", uid).encode(), mapper); // SINK',
            False,
        ),
        (
            'ldapTemplate.search(LdapQueryBuilder.query().where("uid").is(uid), mapper); // SINK',
            False,
        ),
        (
            'ctx.search("ou=people", "(uid={0})", new Object[] {uid}, controls); // SINK',
            False,
        ),
        (
            'ldapTemplate.search("", new HardcodedFilter("(uid=" + uid + ")").encode(), mapper); // SINK',
            True,
        ),
        (
            'String safe = LdapEncoder.filterEncode(uid);\n    ctx.search("ou=people", "(uid=" + uid + ")", controls); // SINK',
            True,
        ),
        (
            'ldapTemplate.search(LdapQueryBuilder.query().filter("(uid=" + uid + ")"), mapper); // SINK',
            True,
        ),
    ],
)
def test_ldap_values_escaped_by_an_encoder_are_not_injection(
    tmp_path, statement, reported
):
    code = (
        "import javax.servlet.http.*;\n"
        "import javax.naming.directory.*;\n"
        "import javax.naming.ldap.Rdn;\n"
        "import org.springframework.ldap.core.LdapTemplate;\n"
        "import org.springframework.ldap.filter.*;\n"
        "import org.springframework.ldap.query.LdapQueryBuilder;\n"
        "import org.springframework.ldap.support.LdapEncoder;\n\n"
        "class App {\n"
        "  private LdapTemplate ldapTemplate;\n"
        "  void run(HttpServletRequest request, DirContext ctx, SearchControls controls, Object mapper) throws Exception {\n"
        '    String uid = request.getParameter("uid");\n'
        f"    {statement}\n"
        "  }\n}\n"
    )
    hits = _findings_on(_scan_java(tmp_path, code), _marked_line(code), "SKY-D239")
    assert bool(hits) is reported
