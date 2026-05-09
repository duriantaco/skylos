from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.java.core import JavaCore
from skylos.visitors.languages.java.flow import scan_java_security_flows
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


def test_tainted_session_attribute_flags_trust_boundary(tmp_path):
    findings = _scan_java(
        tmp_path,
        """import javax.servlet.http.*;

class App {
  void run(HttpServletRequest request) {
    String param = request.getParameter("user");
    request.getSession().setAttribute("userid", param);
  }
}
""",
    )
    assert "trust_boundary" in _categories(findings)


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
