import json

import pytest

from skylos.analyzer import analyze


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (
            ".cs",
            "public class Active { private int count; public int Read() { return count; } }\n"
            "public class Dormant { private int count; }\n",
        ),
        (
            ".dart",
            "class Active { static int _count=0; int read()=>_count++; }\n"
            "class Dormant { static int _count=0; }\n"
            "void main() { Active().read(); Dormant(); }\n",
        ),
    ],
)
def test_same_named_native_fields_keep_their_own_read_evidence(
    tmp_path, suffix, source
):
    if suffix == ".dart":
        pytest.importorskip("tree_sitter_dart_orchard")
    (tmp_path / ("main" + suffix)).write_text(source)
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    names = {item["full_name"] for item in result.get("unused_variables", [])}
    field = "_count" if suffix == ".dart" else "count"
    assert f"Active.{field}" not in names
    assert f"Dormant.{field}" in names
