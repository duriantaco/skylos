"""One-line notes about what a scan left out on purpose.

A default scan skips generated/vendored files. It must never do that
silently: these lines tell the user how much was left out and the flag that
brings it back.
"""

from __future__ import annotations

_GENERATED_REASON_NOUNS = {
    "django_migration": ("Django migration", "Django migrations"),
    "vendored_static_lib": ("static/**/lib file", "static/**/lib files"),
    "minified": ("minified file", "minified files"),
    "vendored_banner": ("vendored-library file", "vendored-library files"),
}


def scope_note_lines(result: dict) -> list[str]:
    summary = result.get("analysis_summary") if isinstance(result, dict) else None
    if not isinstance(summary, dict):
        return []
    lines = []
    generated = _generated_note(summary.get("generated_files"))
    if generated:
        lines.append(generated)
    return lines


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
