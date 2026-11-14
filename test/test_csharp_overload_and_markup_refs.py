from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze


def _write(root: Path, name: str, source: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _unused(root: Path, category: str) -> list[tuple[str, int]]:
    result = json.loads(analyze(str(root), conf=0, grep_verify=False))
    return sorted(
        (item["full_name"], item["line"]) for item in result.get(category, [])
    )


def test_same_arity_overloads_stay_and_other_arity_is_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Events.cs",
        """namespace Demo.Events;

public class Record
{
    internal void Add(string text)
    {
    }

    internal void Add(int code)
    {
    }

    internal void Add(int code, int level)
    {
    }
}
""",
    )
    _write(
        tmp_path,
        "Program.cs",
        """using Demo.Events;

public static class Program
{
    public static void Main()
    {
        Use(new Record(), 3);
    }

    private static void Use(Record record, int code)
    {
        record.Add(code);
    }
}
""",
    )

    assert _unused(tmp_path, "unused_functions") == [("Demo.Events.Record.Add", 13)]


def test_markup_comment_and_other_names_do_not_keep_methods(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Panel.xaml",
        """<Page>
    <!-- <Button Clicked="OnRetired" /> -->
    <Button Clicked="OnSave" />
</Page>
""",
    )
    _write(
        tmp_path,
        "Panel.xaml.cs",
        """namespace Demo.Views;

public partial class Panel
{
    private void OnSave(object sender, object args)
    {
    }

    private void OnRetired(object sender, object args)
    {
    }

    private void OnOrphan(object sender, object args)
    {
    }
}
""",
    )

    assert _unused(tmp_path, "unused_functions") == [
        ("Demo.Views.Panel.OnOrphan", 13),
        ("Demo.Views.Panel.OnRetired", 9),
    ]
