"""Same-named Java, Kotlin and Rust definitions in different files stay separate.

A reference reaches the same-named members its file can see (its own file,
then its package or imports, then its crate). Overloads in one file share
one definition, because name-only references cannot tell them apart.
"""

import json
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _findings(tmp_path):
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    found = set()
    for section in ("unused_functions", "unused_classes", "unused_imports"):
        for item in result.get(section, []):
            path = Path(item["file"]).resolve().relative_to(tmp_path.resolve())
            found.add((section, path.as_posix(), item["name"]))
    return found


def test_unused_member_is_reported_when_another_package_uses_the_same_name(tmp_path):
    java = "src/main/java/com/acme"
    _write(
        tmp_path,
        f"{java}/a/Util.java",
        """
        package com.acme.a;

        public class Util {
            public static String slug(String value) {
                return clean(value) + Helper.twice(2);
            }

            private static String clean(String value) {
                return value.trim();
            }
        }
        """,
    )
    _write(
        tmp_path,
        f"{java}/a/Helper.java",
        """
        package com.acme.a;

        class Helper {
            static int twice(int value) {
                return value * 2;
            }
        }
        """,
    )
    _write(
        tmp_path,
        f"{java}/b/Util.java",
        """
        package com.acme.b;

        public class Util {
            public static String slug(String value) {
                return value;
            }

            private static String clean(String value) {
                return value.strip();
            }
        }
        """,
    )
    _write(
        tmp_path,
        f"{java}/b/Helper.java",
        """
        package com.acme.b;

        class Helper {
            static int twice(int value) {
                return value + value;
            }
        }
        """,
    )
    _write(
        tmp_path,
        f"{java}/app/Main.java",
        """
        package com.acme.app;

        import com.acme.a.Util;

        public class Main {
            public static void main(String[] args) {
                System.out.println(Util.slug(args[0]));
            }
        }
        """,
    )

    found = _findings(tmp_path)

    assert (
        "unused_functions",
        "src/main/java/com/acme/b/Util.java",
        "Util.clean",
    ) in found
    assert ("unused_classes", "src/main/java/com/acme/b/Helper.java", "Helper") in found
    assert not any("/a/" in path for _section, path, _name in found)
    assert not any(section == "unused_imports" for section, _path, _name in found)


def test_overloads_in_one_file_share_liveness(tmp_path):
    _write(
        tmp_path,
        "src/main/java/com/acme/Formatter.java",
        """
        package com.acme;

        public class Formatter {
            public static String render(int value) {
                return format(value);
            }

            private static String format(int value) {
                return Integer.toString(value);
            }

            private static String format(String value) {
                return value.trim();
            }

            private static String pad(int value) {
                return " " + value;
            }

            private static String pad(String value) {
                return " " + value;
            }
        }
        """,
    )

    names = [name for _section, _path, name in _findings(tmp_path)]

    assert names == ["Formatter.pad"]


def test_kotlin_and_rust_members_keep_their_own_identity(tmp_path):
    for package, body in (("a", "clean(value)"), ("b", "value.lowercase()")):
        _write(
            tmp_path,
            f"kotlin/src/main/kotlin/com/acme/{package}/Util.kt",
            f"""
            package com.acme.{package}

            class Util {{
                fun slug(value: String): String = {body}

                private fun clean(value: String): String = value.trim()
            }}
            """,
        )
    _write(tmp_path, "rust/Cargo.toml", '[workspace]\nmembers = ["x", "y"]\n')
    for crate, body in (("x", "helper(value)"), ("y", "value")):
        _write(
            tmp_path,
            f"rust/{crate}/Cargo.toml",
            f'[package]\nname = "{crate}"\nversion = "0.1.0"\nedition = "2021"\n',
        )
        _write(
            tmp_path,
            f"rust/{crate}/src/lib.rs",
            f"""
            fn helper(value: i32) -> i32 {{
                value + 1
            }}

            pub fn run(value: i32) -> i32 {{
                {body}
            }}
            """,
        )

    found = _findings(tmp_path)

    assert (
        "unused_functions",
        "kotlin/src/main/kotlin/com/acme/b/Util.kt",
        "Util.clean",
    ) in found
    assert ("unused_functions", "rust/y/src/lib.rs", "helper") in found
    assert not any("/a/" in path or "/x/" in path for _s, path, _n in found)


JVM_SOURCES = {
    "java": (
        "package {package};\n\n{header}\n",
        "public class Util {{ {modifier} static String slug(String v) {{ return v; }} }}\n",
        'public class Main {{ public static void main(String[] a) {{ System.out.println(Util.slug("x")); }} }}\n',
    ),
    "kt": (
        "package {package}\n\n{header}\n",
        "object Util {{\n    {modifier} fun slug(v: String): String = v\n}}\n",
        'fun main() {{\n    println(Util.slug("x"))\n}}\n',
    ),
}


@pytest.mark.parametrize(
    ("extension", "package", "header", "b_imported"),
    [
        ("java", "app", "import a.Util;\n/*\nimport b.Util;\n*/", False),
        ("java", "app", "import a.Util;\n// import b.Util;", False),
        ("java", "app", 'import a.Util;\nclass Doc { String t = """\nimport b.Util;\n"""; }', False),
        ("java", "a", "/* moved to b */ import b.Util;", True),
        ("kt", "app", "import a.Util\n/*\nimport b.Util\n*/", False),
        ("kt", "app", 'import a.Util\nval doc = """\nimport b.Util\n"""', False),
        ("kt", "a", "/* moved to b */ import b.Util", True),
    ],
)
def test_only_real_jvm_imports_make_a_same_named_class_visible(
    tmp_path, extension, package, header, b_imported
):
    file_header, util, main = JVM_SOURCES[extension]
    for owner, modifier in (("a", "public"), ("b", "private")):
        source = file_header.format(package=owner, header="")
        _write(tmp_path, f"{owner}/Util.{extension}", source + util.format(modifier=modifier))
    source = file_header.format(package=package, header=header)
    _write(tmp_path, f"{package}/Main.{extension}", source + main.format())

    found = _findings(tmp_path)

    unused = ("unused_functions", f"b/Util.{extension}", "Util.slug") in found
    assert unused is not b_imported
