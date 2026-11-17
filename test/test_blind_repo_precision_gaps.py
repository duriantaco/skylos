"""False positives found on blind repositories, each with a negative control.

- A module a known distribution ships (``pythoncom`` in pywin32, ``pylab`` in
  matplotlib) is undeclared at most, never hallucinated.
- ``a, b = helper()`` reads only the matching item of tuple returns.
- A containment check through a once-bound ``commonpath`` result, and a project
  helper whose body proves containment, clear SKY-D215.
"""

import json
import textwrap

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.analyzer import analyze
from skylos.core.python_distributions import CURATED_IMPORT_PATHS
from test.fixture_paths import write_fixture


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def test_curated_provider_modules_map_to_their_distribution(monkeypatch):
    monkeypatch.setattr(dep, "_IMPORT_TO_DIST_MAPPING", None)
    mapping = dep._load_import_to_dist_mapping()
    assert mapping["pythoncom"] == "pywin32"
    assert mapping["win32com"] == "pywin32"
    assert mapping["pylab"] == "matplotlib"
    # Ambiguous curated modules are not guessed.
    providers = [
        dist for dist, paths in CURATED_IMPORT_PATHS.items() if "notifications" in paths
    ]
    assert len(providers) > 1
    assert mapping.get("notifications") not in providers


def _danger(tmp_path):
    report = json.loads(analyze(str(tmp_path), enable_danger=True))
    return {
        (row["rule_id"], row["file"].replace("\\", "/").rsplit("/", 1)[-1], row["line"])
        for row in report.get("danger", [])
        if row["rule_id"] == "SKY-D215"
    }


def _route(tmp_path, body):
    write_fixture(
        tmp_path, "pyproject.toml", '[project]\nname = "proj"\n', overwrite=True
    )
    _write(tmp_path, "app.py", body)


def test_containment_check_through_a_once_bound_commonpath_result(tmp_path):
    _route(
        tmp_path,
        """
        import os
        from fastapi import FastAPI

        app = FastAPI()
        BASE = "/srv/files"


        @app.get("/f/{file_path:path}")
        def read_file(file_path: str):
            base_real = os.path.realpath(BASE)
            resolved = os.path.realpath(os.path.join(base_real, file_path))
            common = os.path.commonpath([base_real, resolved])
            if common != base_real:
                raise ValueError("outside")
            with open(resolved, "rb") as handle:
                return handle.read()
        """,
    )
    assert not _danger(tmp_path)


def test_rebinding_the_checked_path_after_the_check_is_still_reported(tmp_path):
    _route(
        tmp_path,
        """
        import os
        from fastapi import FastAPI

        app = FastAPI()
        BASE = "/srv/files"


        @app.get("/f/{file_path:path}")
        def read_file(file_path: str):
            base_real = os.path.realpath(BASE)
            resolved = os.path.realpath(os.path.join(base_real, file_path))
            common = os.path.commonpath([base_real, resolved])
            if common != base_real:
                raise ValueError("outside")
            resolved = os.path.join(base_real, file_path)
            with open(resolved, "rb") as handle:
                return handle.read()
        """,
    )
    assert _danger(tmp_path)


_HELPERS = {
    "proven": """
        import os


        def resolve_within(base_dir, unsafe_path):
            base_real = os.path.realpath(base_dir)
            resolved = os.path.realpath(os.path.join(base_real, unsafe_path))
            if os.path.commonpath([base_real, resolved]) != base_real:
                raise ValueError("outside")
            return resolved
        """,
    "no_check": """
        import os


        def resolve_within(base_dir, unsafe_path):
            return os.path.realpath(os.path.join(base_dir, unsafe_path))
        """,
    "checks_another_value": """
        import os


        def resolve_within(base_dir, unsafe_path):
            base_real = os.path.realpath(base_dir)
            checked = os.path.realpath(os.path.join(base_real, "fixed"))
            if os.path.commonpath([base_real, checked]) != base_real:
                raise ValueError("outside")
            return os.path.join(base_real, unsafe_path)
        """,
    "early_return": """
        import os


        def resolve_within(base_dir, unsafe_path):
            base_real = os.path.realpath(base_dir)
            resolved = os.path.realpath(os.path.join(base_real, unsafe_path))
            if unsafe_path.endswith(".mp4"):
                return resolved
            if os.path.commonpath([base_real, resolved]) != base_real:
                raise ValueError("outside")
            return resolved
        """,
}


@pytest.mark.parametrize(
    "helper, reported",
    [
        ("proven", False),
        ("no_check", True),
        ("checks_another_value", True),
        ("early_return", True),
    ],
)
def test_project_containment_helper_is_proven_from_its_body(tmp_path, helper, reported):
    write_fixture(
        tmp_path, "pyproject.toml", '[project]\nname = "proj"\n', overwrite=True
    )
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/utils/__init__.py", "")
    _write(tmp_path, "app/utils/file_security.py", _HELPERS[helper])
    _write(
        tmp_path,
        "app/main.py",
        """
        from fastapi import FastAPI

        from app.utils import file_security

        app = FastAPI()


        def _wrapped(base_dir, unsafe_path, request_id):
            try:
                return file_security.resolve_within(base_dir, unsafe_path)
            except ValueError:
                raise RuntimeError(request_id)


        @app.get("/f/{file_path:path}")
        def read_file(file_path: str, request_id: str):
            resolved = _wrapped("/srv/files", file_path, request_id)
            with open(resolved, "rb") as handle:
                return handle.read()
        """,
    )
    assert bool(_danger(tmp_path)) is reported


def _staging_project(tmp_path, returned):
    # Route and helpers in different modules, as in the repository where this
    # was found: the helper parameter is resolved through its callers.
    write_fixture(
        tmp_path, "pyproject.toml", '[project]\nname = "proj"\n', overwrite=True
    )
    _write(tmp_path, "svc/__init__.py", "")
    _write(
        tmp_path,
        "svc/staging.py",
        f"""
        import os
        import tempfile


        def _remove_staged(file_path):
            if file_path and os.path.exists(file_path):
                os.remove(file_path)


        def _stage(filename):
            safe_name = filename.replace("/", "_")
            descriptor, temp_path = tempfile.mkstemp(suffix=".bin")
            os.close(descriptor)
            return {returned}


        def save_upload(filename):
            name, staged = _stage(filename)
            _remove_staged(staged)
            return name
        """,
    )
    _write(
        tmp_path,
        "svc/routes.py",
        """
        from fastapi import FastAPI, UploadFile

        from svc import staging

        app = FastAPI()


        @app.post("/upload")
        def upload(file: UploadFile):
            return staging.save_upload(file.filename)
        """,
    )


def test_unpacked_tuple_item_from_a_temporary_path_is_not_request_data(tmp_path):
    _staging_project(tmp_path, "safe_name, temp_path")
    assert not _danger(tmp_path)


def test_unpacked_tuple_item_carrying_request_data_is_still_reported(tmp_path):
    _staging_project(tmp_path, "temp_path, safe_name")
    assert _danger(tmp_path)


def test_editing_a_proven_helper_is_seen_by_the_next_scan_in_the_same_process(tmp_path):
    write_fixture(
        tmp_path, "pyproject.toml", '[project]\nname = "proj"\n', overwrite=True
    )
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/utils/__init__.py", "")
    _write(tmp_path, "app/utils/file_security.py", _HELPERS["proven"])
    _write(
        tmp_path,
        "app/main.py",
        """
        from fastapi import FastAPI

        from app.utils import file_security

        app = FastAPI()


        @app.get("/f/{file_path:path}")
        def read_file(file_path: str):
            resolved = file_security.resolve_within("/srv/files", file_path)
            with open(resolved, "rb") as handle:
                return handle.read()
        """,
    )
    assert not _danger(tmp_path)
    _write(
        tmp_path, "app/utils/file_security.py", _HELPERS["no_check"] + "\n\n# edited\n"
    )
    assert _danger(tmp_path)
