"""One-line notes about what a scan left out on purpose.

A default scan skips generated/vendored files. It must never do that
silently: these lines tell the user how much was left out and the flag that
brings it back.
"""

from __future__ import annotations

_GENERATED_REASON_NOUNS = {
    "django_migration": ("Django migration", "Django migrations"),
    "vendored_static_lib": ("web-root library file", "web-root library files"),
    "minified": ("minified file", "minified files"),
    "vendored_banner": ("vendored-library file", "vendored-library files"),
    "generated_source": ("generated source file", "generated source files"),
}


def scope_note_lines(result: dict) -> list[str]:
    summary = result.get("analysis_summary") if isinstance(result, dict) else None
    if not isinstance(summary, dict):
        return []
    lines = []
    generated = _generated_note(summary.get("generated_files"))
    if generated:
        lines.append(generated)
    lines.extend(_below_threshold_notes(summary.get("dead_code_below_threshold")))
    lines.extend(_experimental_dead_code_notes(summary.get("dead_code_experimental")))
    bare_noqa = _count(summary.get("bare_noqa_security_findings"))
    if bare_noqa:
        noun = "finding sits" if bare_noqa == 1 else "findings sit"
        lines.append(
            f"{bare_noqa:,} HIGH/CRITICAL security {noun} on a bare `# noqa`, "
            "which does not hide security findings; to accept one, use "
            "`# skylos: ignore[SKY-...] <reason>`."
        )
    return lines


def _below_threshold_notes(below) -> list[str]:
    if not isinstance(below, dict):
        return []
    info = below.get("unused_parameters")
    count = _count(info.get("count")) if isinstance(info, dict) else 0
    if not count:
        return []
    noun = "unused parameter is" if count == 1 else "unused parameters are"
    show_with = info.get("show_with") or "--confidence 50"
    note = (
        f"{count:,} {noun} below the default confidence threshold "
        f"(callback and override signatures often require them); "
        f"use {show_with} to see them."
    )
    return [note]


_EXPERIMENTAL_LANGUAGE_NAMES = {"rust": "Rust"}


def _experimental_dead_code_notes(experimental) -> list[str]:
    if not isinstance(experimental, dict):
        return []
    notes = []
    for language, info in sorted(experimental.items()):
        if not isinstance(info, dict) or info.get("listed") is not False:
            continue
        name = _EXPERIMENTAL_LANGUAGE_NAMES.get(str(language), str(language))
        notes.append(
            f"{name} dead code is experimental and is not listed at the default "
            f"confidence threshold; use {info.get('show_with') or '--confidence 40'} "
            f"to see {name} candidates."
        )
    return notes


def _generated_note(generated) -> str | None:
    if not isinstance(generated, dict):
        return None
    count = _count(generated.get("skipped_count"))
    if not count:
        return None
    by_reason = generated.get("by_reason")
    parts = []
    if isinstance(by_reason, dict):
        for reason, reason_count in sorted(
            by_reason.items(), key=lambda item: (-_count(item[1]), str(item[0]))
        ):
            reason_count = _count(reason_count)
            if not reason_count:
                continue
            singular, plural = _GENERATED_REASON_NOUNS.get(
                str(reason), (str(reason), str(reason))
            )
            noun = singular if reason_count == 1 else plural
            parts.append(f"{reason_count:,} {noun}")
    detail = f" ({', '.join(parts)})" if parts else ""
    noun = "file" if count == 1 else "files"
    return (
        f"Skipped {count:,} generated/vendored {noun}{detail}; "
        "use --include-generated to scan them."
    )


def _count(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(value, 0)
