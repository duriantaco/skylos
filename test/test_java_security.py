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
