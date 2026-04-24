from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.java import scan_java_file


def _scan_java(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "App.java"
    file_path.write_text(code, encoding="utf-8")
    return scan_java_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


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
