from time import perf_counter

from skylos.visitors.languages.statement_scan import iter_semicolon_assignments


def test_iter_semicolon_assignments_extracts_java_and_typescript_aliases():
    source = """
    final String name = entry.getName();
    const fileName: string = entry.fileName;
    outputPath = path.join(
      "/tmp/out",
      fileName
    );
    """

    events = iter_semicolon_assignments(source)

    assert events[0][1:] == ("name", "entry.getName()")
    assert events[1][1:] == ("fileName", "entry.fileName")
    assert events[2][1] == "outputPath"
    assert "fileName" in events[2][2]


def test_iter_semicolon_assignments_handles_semicolonless_alias_storm_quickly():
    source = "\n".join(
        f"const alias{index} = entry.path" for index in range(5000)
    )

    started = perf_counter()
    events = iter_semicolon_assignments(source)
    elapsed = perf_counter() - started

    assert len(events) == 5000
    assert elapsed < 2.0
