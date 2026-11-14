#!/usr/bin/env python3
"""Build the Skylos rule handbook as one HTML file and a PDF.

Inputs, all under docs/handbook/:

- rules/<RULE-ID>.yaml: one page per rule (schema in docs/handbook/README.md);
- families.yaml: the book's rule families, their intros and which catalog
  rules belong to each;
- intro/*.md: the front matter, in a small Markdown subset;
- cloud/*.md: the "Using Skylos Cloud" guide, in the same subset, with
  screenshots from img/cloud/ and the feature list in cloud/manifest.yaml;
- handbook.css: the page style.

The rule list comes from skylos/rules/catalog.py. Rules without a page are
listed as "not yet written" in the coverage report and left out of a pilot
build; a full build refuses to run while any are missing.

--verify writes every example into a scratch folder and runs the real
skylos CLI on it, with HOME pointed at the scratch folder and --no-upload.
A flagged example must produce its rule ID, a not-flagged example and a
verifiable fix must not.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import difflib
import hashlib
import html
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

import yaml
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.util import ClassNotFound

REPO_ROOT = Path(__file__).resolve().parent.parent
HANDBOOK_DIR = REPO_ROOT / "docs" / "handbook"
RULES_DIR = HANDBOOK_DIR / "rules"
INTRO_DIR = HANDBOOK_DIR / "intro"
CLOUD_DIR = HANDBOOK_DIR / "cloud"
CLOUD_MANIFEST_FILE = CLOUD_DIR / "manifest.yaml"
IMAGE_DIR = HANDBOOK_DIR / "img"
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
IMAGE_PATTERN = re.compile(r"^!\[([^\]]*)\]\(([^)\s]+)\)$")
CLOUD_STATUSES = ("covered", "not_available")
SHOT_MM_PER_PIXEL = 0.124
SHOT_MAX_WIDTH_MM = 176
SHOT_MAX_HEIGHT_MM = 125
FAMILIES_FILE = HANDBOOK_DIR / "families.yaml"
PENDING_FILE = HANDBOOK_DIR / "pending.yaml"
CSS_FILE = HANDBOOK_DIR / "handbook.css"
DEFAULT_OUTPUT = REPO_ROOT / "build" / "handbook" / "skylos-handbook.pdf"
DEFAULT_CHROME = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
PAGE_SEVERITIES = SEVERITIES + ("VARIES", "UNRATED")
SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "VARIES": "Varies",
    "UNRATED": "No severity",
}
RULE_REQUIRED = (
    "id",
    "gate",
    "title",
    "family",
    "severity",
    "languages",
    "what_it_is",
    "why_it_matters",
    "how_skylos_decides",
    "source_refs",
    "flagged_example",
    "not_flagged_example",
    "fix",
    "false_alarms_and_suppression",
    "related",
)
RULE_OPTIONAL = ("cwe", "severity_note", "run_with", "verify", "more_examples")
EXAMPLE_KEYS = {
    "language",
    "filename",
    "code",
    "files",
    "setup",
    "base_files",
    "scan_flags",
    "expect_file",
    "expect_line",
    "why",
    "verify",
}
FILE_KEYS = {"filename", "code", "language", "deleted"}
SETUPS = ("none", "git", "git_diff")
FIX_KEYS = {"explanation", "code", "language", "filename", "scan_flags"}
FALSE_ALARM_KEYS = {"misfires", "suppress"}
SUPPRESS_KEYS = {"text", "code", "language", "check"}
CHECK_KINDS = ("inline", "config", "baseline", "example")
CHECK_EXPECTS = ("hidden", "reported")
GATE_KEYS = {"full", "diff", "opt_in", "note"}
GATE_STATES = {
    "counted": "counted toward the gate limits",
    "critical_blocks": "counted toward the gate limits; a CRITICAL finding fails the gate on its own",
    "listed": "listed, not counted by the gate",
    "blocks": "fails the gate on its own",
    "not_run": "not checked",
}
MORE_EXAMPLE_KEYS = {"flagged", "not_flagged"}
HASH_COMMENT_LANGUAGES = {
    "python",
    "yaml",
    "toml",
    "shell",
    "bash",
    "ruby",
    "dockerfile",
    "terraform",
    "ini",
}
SLASH_COMMENT_LANGUAGES = {
    "typescript",
    "javascript",
    "go",
    "java",
    "kotlin",
    "csharp",
    "rust",
    "dart",
    "cpp",
    "swift",
    "php",
    "solidity",
}
CHECK_MARKER_REASON = "handbook check"
SOURCE_REF_KEYS = {"path", "symbol", "note"}
LANGUAGE_NAMES = {
    "python": "Python",
    "typescript": "TypeScript",
    "tsx": "TSX",
    "javascript": "JavaScript",
    "jsx": "JSX",
    "go": "Go",
    "java": "Java",
    "kotlin": "Kotlin",
    "php": "PHP",
    "rust": "Rust",
    "ruby": "Ruby",
    "dart": "Dart",
    "csharp": "C#",
    "cpp": "C++",
    "shell": "Shell",
    "bash": "Shell",
    "yaml": "YAML",
    "json": "JSON",
    "toml": "TOML",
    "ini": "INI",
    "dockerfile": "Dockerfile",
    "terraform": "Terraform",
    "solidity": "Solidity",
    "markdown": "Markdown",
    "md": "Markdown",
    "html": "HTML",
    "diff": "Diff",
    "text": "Text",
}
LEXER_NAMES = {
    "shell": "bash",
    "csharp": "csharp",
    "terraform": "terraform",
    "text": "text",
    "jsx": "jsx",
    "tsx": "tsx",
}
RULE_ID_PATTERN = re.compile(r"\bSKY-(?:CIRC|SCA-[A-Z]+[0-9]{3}|[A-Z]+[0-9]{3})\b")
PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")
FRAGMENT_PATTERN = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")
MAX_CODE_COLUMNS = 88
PAGE_NUMBER_PLACEHOLDER = "000"
VERIFY_TIMEOUT_SECONDS = 300
VERIFY_ENV_KEEP = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "SYSTEMROOT",
    "SKYLOS_GO_BIN",
)


class BuildError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the Skylos rule handbook (HTML and PDF)."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="PDF path. The HTML, coverage report and verify report are "
        "written next to it.",
    )
    parser.add_argument(
        "--mode",
        choices=("pilot", "full"),
        default="pilot",
        help="pilot leaves rules without a page out of the book; full "
        "refuses to build while any catalog rule has no page.",
    )
    parser.add_argument(
        "--rule",
        action="append",
        default=[],
        metavar="RULE-ID",
        help="Only use this rule page (repeatable).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run every example through the skylos CLI before building.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Run the examples through the skylos CLI and stop.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate the pages and write the coverage report only.",
    )
    parser.add_argument(
        "--html-only",
        action="store_true",
        help="Write the HTML but do not print the PDF.",
    )
    parser.add_argument(
        "--skylos",
        default=None,
        help="skylos executable for --verify (default: the console script "
        "next to this Python, else skylos on PATH). The checkout this script "
        "lives in is put first on PYTHONPATH.",
    )
    parser.add_argument(
        "--scratch",
        type=Path,
        default=None,
        help="Scratch folder for --verify (default: a new temporary folder).",
    )
    parser.add_argument(
        "--keep-scratch",
        action="store_true",
        help="Keep the --verify scratch folder.",
    )
    parser.add_argument(
        "--dump-command-reference",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--chrome",
        default=os.environ.get("CHROME_BIN"),
        help="Chrome or Chromium executable for printing.",
    )
    parser.add_argument(
        "--chrome-arg",
        action="append",
        default=[],
        metavar="ARG",
        help="Extra Chrome argument (repeatable), e.g. --chrome-arg=--no-sandbox "
        "on CI runners where Chrome's sandbox is unavailable.",
    )
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO_ROOT))
    if args.dump_command_reference:
        quiet = io.StringIO()
        with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
            reference = collect_command_reference()
        print(json.dumps(reference))
        return 0
    try:
        return run(args)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def run(args) -> int:
    catalog = load_catalog()
    families = load_families(catalog)
    pages, problems = load_pages(catalog, families, set(args.rule))
    for warning in problems["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    if problems["errors"]:
        for error in problems["errors"]:
            print(f"error: {error}", file=sys.stderr)
        raise BuildError(f"{len(problems['errors'])} page problem(s); nothing built")

    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    coverage_path = output.with_name(output.stem + "-coverage.md")
    pending = load_pending(catalog)
    coverage = build_coverage(catalog, families, pages, pending)
    coverage_path.write_text(render_coverage(coverage), encoding="utf-8")
    if coverage["unaccounted"] and not args.rule:
        listed = ", ".join(coverage["unaccounted"][:20])
        raise BuildError(
            f"{len(coverage['unaccounted'])} catalog rule(s) have neither a page nor "
            f"an entry in docs/handbook/pending.yaml: {listed}"
        )
    print(
        f"coverage: {coverage['written']} of {coverage['pages_needed']} rules "
        f"have a page ({coverage['missing']} not yet written; "
        f"{len(coverage['remapped'])} catalog IDs are reported under another "
        f"rule) -> {coverage_path}"
    )
    if args.mode == "full" and coverage["missing"]:
        raise BuildError(
            f"--mode full needs a page for every catalog rule; "
            f"{coverage['missing']} are not yet written (see {coverage_path})"
        )

    verify_path = output.with_name(output.stem + "-verify.json")
    if args.verify or args.verify_only:
        report = verify_pages(pages, args)
        verify_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print_verify_table(report)
        print(f"verify report: {verify_path}")
        if report["failed"]:
            raise BuildError(f"{report['failed']} example check(s) failed")
        if args.verify_only:
            return 0

    cloud_errors = cloud_problems()
    if cloud_errors:
        for error in cloud_errors:
            print(f"error: {error}", file=sys.stderr)
        raise BuildError(f"{len(cloud_errors)} Cloud guide problem(s); nothing built")

    if args.check:
        return 0

    verify_report = read_verify_report(verify_path)
    intro = load_intro(catalog, families, pages)
    book = Book(catalog, families, pages, intro, verify_report, args.mode)
    book.cloud = load_cloud_chapters()
    book.cloud_manifest = load_cloud_manifest()
    html_path = output.with_suffix(".html")
    page_numbers: dict[str, int] = {}
    html_path.write_text(book.render(page_numbers), encoding="utf-8")
    if args.html_only:
        print(f"html: {html_path}")
        return 0

    chrome = find_chrome(args.chrome)
    page_count = 0
    for _attempt in range(3):
        print_pdf(chrome, html_path, output, args.chrome_arg)
        destinations, page_count = pdf_destinations(
            output.read_bytes()  # skylos: ignore[SKY-D325] the PDF Chrome just printed to --output
        )
        if destinations == page_numbers:
            break
        page_numbers = destinations
        html_path.write_text(book.render(page_numbers), encoding="utf-8")
    else:
        raise BuildError("page numbers did not settle after three print passes")
    missing_targets = sorted(set(book.anchors) - set(page_numbers))
    if missing_targets:
        raise BuildError(
            "the PDF has no destination for: " + ", ".join(missing_targets[:10])
        )
    print(f"html: {html_path}")
    print(f"pdf: {output} ({page_count} pages)")
    return 0


def load_catalog() -> dict[str, dict]:
    from skylos.rules.catalog import get_rule_catalog, get_rule_cwes

    catalog = {}
    for entry in get_rule_catalog():
        item = dict(entry)
        item["cwe"] = list(get_rule_cwes(entry["id"]))
        catalog[entry["id"]] = item
    return catalog


def go_remapped_ids() -> dict[str, str]:
    from skylos.visitors.languages.go.go import _GO_RULE_REMAP

    return dict(_GO_RULE_REMAP)


def catalog_aliases(catalog: dict[str, dict]) -> dict[str, str]:
    """Catalog IDs that are always reported under another rule's ID.

    The Go engine's cross-language findings are renamed before reporting
    (SKY-G211 becomes SKY-D211), so they are documented on that rule's page.
    """
    aliases = {}
    for rule_id, target in go_remapped_ids().items():
        if rule_id in catalog and target in catalog:
            aliases[rule_id] = target
    return aliases


def skylos_version() -> str:
    import skylos

    return str(getattr(skylos, "__version__", "unknown"))


def load_families(catalog: dict[str, dict]) -> list[dict]:
    data = read_yaml(FAMILIES_FILE)
    if not isinstance(data, dict) or not isinstance(data.get("families"), list):
        raise BuildError(f"{FAMILIES_FILE}: expected a 'families' list")
    families = []
    seen = set()
    fallback_count = 0
    for index, item in enumerate(data["families"]):
        where = f"{FAMILIES_FILE.name} family #{index + 1}"
        if not isinstance(item, dict):
            raise BuildError(f"{where}: expected a mapping")
        for key in ("id", "title", "prefixes", "intro"):
            if not item.get(key):
                raise BuildError(f"{where}: missing '{key}'")
        if item["id"] in seen:
            raise BuildError(f"{where}: duplicate id {item['id']}")
        seen.add(item["id"])
        match = item.get("match") or {}
        family = {
            "id": str(item["id"]),
            "title": str(item["title"]),
            "prefixes": str(item["prefixes"]),
            "intro": str(item["intro"]).strip(),
            "categories": [str(value) for value in match.get("categories") or []],
            "ids": [str(value) for value in match.get("ids") or []],
            "fallback": bool(item.get("fallback")),
        }
        if family["fallback"]:
            fallback_count += 1
        families.append(family)
    if fallback_count > 1:
        raise BuildError(f"{FAMILIES_FILE.name}: only one family may be the fallback")
    for rule_id, entry in catalog.items():
        if family_for_rule(entry, families) is None:
            raise BuildError(f"{FAMILIES_FILE.name}: no family matches {rule_id}")
    return families


def family_for_rule(entry: dict, families: list[dict]) -> str | None:
    ordered = [family for family in families if not family["fallback"]]
    ordered += [family for family in families if family["fallback"]]
    for family in ordered:
        if entry["category"] in family["categories"]:
            return family["id"]
        for pattern in family["ids"]:
            if fnmatchcase(entry["id"], pattern):
                return family["id"]
        if family["fallback"]:
            return family["id"]
    return None


def read_yaml(path: Path):
    try:
        with path.open(encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise BuildError(f"missing file: {path}") from exc
    except yaml.YAMLError as exc:
        raise BuildError(f"{path}: invalid YAML: {exc}") from exc


def load_pages(catalog, families, only_ids: set[str]):
    problems = {"errors": [], "warnings": []}
    family_ids = {family["id"] for family in families}
    pages = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        rule_id = path.stem
        if only_ids and rule_id not in only_ids:
            continue
        data, fragment_problems = expand_fragments(path, read_yaml(path))
        problems["errors"].extend(fragment_problems["errors"])
        problems["warnings"].extend(fragment_problems["warnings"])
        page_problems = validate_page(path, data, catalog, families, family_ids)
        aliases = catalog_aliases(catalog)
        if rule_id in aliases:
            page_problems["errors"].append(
                f"rules/{path.name}: {rule_id} is reported as {aliases[rule_id]}; "
                f"describe it on that rule's page"
            )
        problems["errors"].extend(page_problems["errors"])
        problems["warnings"].extend(page_problems["warnings"])
        if not page_problems["errors"]:
            page = dict(data)
            page["cwe"] = list(catalog[rule_id]["cwe"])
            page["catalog"] = catalog[rule_id]
            pages[rule_id] = page
    unknown = sorted(only_ids - set(pages) - {p.stem for p in RULES_DIR.glob("*.yaml")})
    for rule_id in unknown:
        problems["errors"].append(f"--rule {rule_id}: no page at rules/{rule_id}.yaml")
    return pages, problems


def expand_fragments(path, data):
    """Join ``fragments`` and put them where ``{{NAME}}`` appears.

    A secret example would otherwise sit in this repository as a real
    finding; stored in parts, no part looks like a secret.
    """
    problems = {"errors": [], "warnings": []}
    if not isinstance(data, dict) or "fragments" not in data:
        return data, problems
    where = f"rules/{path.name}"
    raw = data["fragments"]
    values = {}
    if not isinstance(raw, dict):
        problems["errors"].append(
            f"{where}: fragments must map NAME to a list of parts"
        )
        raw = {}
    for name, parts in raw.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", str(name)):
            problems["errors"].append(
                f"{where}: fragment name {name} must be UPPER_CASE"
            )
        elif not isinstance(parts, list) or not all(
            isinstance(part, str) for part in parts
        ):
            problems["errors"].append(
                f"{where}: fragment {name} must be a list of strings"
            )
        else:
            values[name] = "".join(parts)
    used = set()

    def substitute(value):
        if isinstance(value, str):

            def replace(match):
                name = match.group(1)
                used.add(name)
                if name not in values:
                    problems["errors"].append(
                        f"{where}: unknown fragment {{{{{name}}}}}"
                    )
                    return match.group(0)
                return values[name]

            return FRAGMENT_PATTERN.sub(replace, value)
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        return value

    expanded = {
        key: substitute(value) for key, value in data.items() if key != "fragments"
    }
    for name in sorted(set(values) - used):
        problems["warnings"].append(f"{where}: fragment {name} is never used")
    return expanded, problems


def validate_page(path, data, catalog, families, family_ids):
    where = f"rules/{path.name}"
    if not isinstance(data, dict):
        return {"errors": [f"{where}: expected a mapping"], "warnings": []}
    errors = validate_fields(where, data)
    if errors:
        return {"errors": errors, "warnings": []}
    entry = catalog.get(data["id"])
    if data["id"] != path.stem:
        errors.append(f"{where}: id {data['id']} does not match the file name")
    if entry is None:
        errors.append(f"{where}: {data['id']} is not in skylos/rules/catalog.py")
        return {"errors": errors, "warnings": []}
    family_problems = validate_family(where, data, entry, families, family_ids)
    text_problems = validate_text(where, data)
    errors += family_problems["errors"] + text_problems["errors"]
    warnings = family_problems["warnings"] + text_problems["warnings"]
    errors += validate_severity(where, data, entry)
    errors += validate_source_refs(where, data["source_refs"])
    errors += validate_example(where, "flagged_example", data["flagged_example"])
    errors += validate_example(
        where, "not_flagged_example", data["not_flagged_example"]
    )
    if not data["not_flagged_example"].get("why"):
        errors.append(f"{where}: not_flagged_example needs 'why'")
    errors += validate_fix(where, data["fix"])
    errors += validate_false_alarms(where, data["false_alarms_and_suppression"])
    errors += validate_suppress_checks(where, data)
    errors += validate_related(where, data, catalog)
    errors += validate_gate(where, data["gate"])
    errors += validate_verify(f"{where}: verify", data.get("verify"))
    errors += validate_more_examples(where, data.get("more_examples"))
    if not errors:
        warnings += code_width_warnings(where, data)
    return {"errors": errors, "warnings": warnings}


def validate_fields(where, data) -> list[str]:
    errors = []
    for key in RULE_REQUIRED:
        if key not in data or data[key] in (None, "", []):
            errors.append(f"{where}: missing '{key}'")
    for key in data:
        if key not in RULE_REQUIRED and key not in RULE_OPTIONAL:
            errors.append(f"{where}: unknown field '{key}'")
    for key in ("flagged_example", "not_flagged_example", "fix"):
        if key in data and not isinstance(data[key], dict):
            errors.append(f"{where}: {key} must be a mapping")
    return errors


def validate_family(where, data, entry, families, family_ids) -> dict:
    if data["family"] not in family_ids:
        return {
            "errors": [f"{where}: unknown family '{data['family']}'"],
            "warnings": [],
        }
    expected = family_for_rule(entry, families)
    if expected == data["family"]:
        return {"errors": [], "warnings": []}
    warning = (
        f"{where}: family '{data['family']}' differs from families.yaml "
        f"matching ('{expected}')"
    )
    return {"errors": [], "warnings": [warning]}


def validate_severity(where, data, entry) -> list[str]:
    errors = []
    severity = data["severity"]
    if severity not in PAGE_SEVERITIES:
        errors.append(f"{where}: severity must be one of {', '.join(PAGE_SEVERITIES)}")
    elif entry.get("severity") and severity != entry["severity"]:
        errors.append(
            f"{where}: severity {severity} differs from the catalog ({entry['severity']})"
        )
    if severity in ("VARIES", "UNRATED") and not data.get("severity_note"):
        errors.append(f"{where}: severity {severity} needs a severity_note")
    if "cwe" in data:
        listed = [str(value) for value in data["cwe"] or []]
        if listed != list(entry["cwe"]):
            errors.append(
                f"{where}: cwe {listed} differs from the catalog {list(entry['cwe'])}"
            )
    return errors


def validate_text(where, data) -> dict:
    errors = []
    warnings = []
    languages = data["languages"]
    if not isinstance(languages, list) or not all(
        isinstance(value, str) and value for value in languages
    ):
        errors.append(f"{where}: languages must be a list of names")
    for key in ("title", "what_it_is", "why_it_matters"):
        if not isinstance(data[key], str):
            errors.append(f"{where}: {key} must be text")
    sentence_limits = (("what_it_is", 2, 3), ("why_it_matters", 1, 3))
    for key, low, high in sentence_limits:
        if isinstance(data[key], str):
            count = sentence_count(data[key])
            if count < low or count > high:
                warnings.append(
                    f"{where}: {key} has {count} sentences (aim for {low}-{high})"
                )
    steps = data["how_skylos_decides"]
    if not isinstance(steps, list) or len(steps) < 2:
        errors.append(f"{where}: how_skylos_decides must list at least two steps")
    elif not all(isinstance(step, str) and step.strip() for step in steps):
        errors.append(f"{where}: how_skylos_decides steps must be text")
    return {"errors": errors, "warnings": warnings}


def validate_related(where, data, catalog) -> list[str]:
    related = data["related"]
    if not isinstance(related, list):
        return [f"{where}: related must be a list of rule IDs"]
    errors = []
    for other in related:
        if other not in catalog:
            errors.append(f"{where}: related rule {other} is not in the catalog")
        elif other == data["id"]:
            errors.append(f"{where}: related lists the rule itself")
    return errors


def sentence_count(text: str) -> int:
    stripped = re.sub(r"`[^`]*`", "x", text.strip())
    stripped = re.sub(r"\b(e\.g|i\.e|etc|vs)\.", "x", stripped)
    return len([part for part in re.split(r"[.!?](?:\s+|$)", stripped) if part.strip()])


def validate_source_refs(where, refs) -> list[str]:
    errors = []
    if not isinstance(refs, list) or not refs:
        return [f"{where}: source_refs must be a non-empty list"]
    for index, ref in enumerate(refs):
        label = f"{where}: source_refs[{index}]"
        if not isinstance(ref, dict) or not ref.get("path") or not ref.get("symbol"):
            errors.append(f"{label}: needs 'path' and 'symbol'")
            continue
        unknown = set(ref) - SOURCE_REF_KEYS
        if unknown:
            errors.append(f"{label}: unknown key(s) {sorted(unknown)}")
        target = REPO_ROOT / str(ref["path"])
        if not target.is_file():
            errors.append(f"{label}: {ref['path']} does not exist")
            continue
        text = target.read_text(encoding="utf-8", errors="replace")
        if str(ref["symbol"]) not in text:
            errors.append(f"{label}: '{ref['symbol']}' not found in {ref['path']}")
    return errors


def validate_relative_name(label, name) -> list[str]:
    if not isinstance(name, str) or not name:
        return [f"{label}: filename must be text"]
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or "\\" in name:
        return [f"{label}: filename must be a relative path inside the example"]
    return []


def validate_file_entries(label, entries, *, allow_deleted) -> list[str]:
    errors = []
    if not isinstance(entries, list) or not entries:
        return [f"{label}: expected a non-empty list of files"]
    names = set()
    for index, entry in enumerate(entries):
        item_label = f"{label}[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{item_label}: expected a mapping")
            continue
        unknown = set(entry) - FILE_KEYS
        if unknown:
            errors.append(f"{item_label}: unknown key(s) {sorted(unknown)}")
        errors.extend(validate_relative_name(item_label, entry.get("filename")))
        if entry.get("filename") in names:
            errors.append(f"{item_label}: duplicate filename {entry.get('filename')}")
        names.add(entry.get("filename"))
        if entry.get("deleted"):
            if not allow_deleted:
                errors.append(f"{item_label}: 'deleted' needs setup: git_diff")
        elif not isinstance(entry.get("code"), str):
            errors.append(f"{item_label}: needs 'code'")
    return errors


def validate_example(where, key, example) -> list[str]:
    label = f"{where}: {key}"
    if not isinstance(example, dict):
        return [f"{label}: expected a mapping"]
    errors = []
    unknown = set(example) - EXAMPLE_KEYS
    if unknown:
        errors.append(f"{label}: unknown key(s) {sorted(unknown)}")
    if not key.endswith("not_flagged_example") and "why" in example:
        errors.append(f"{label}: 'why' belongs to not_flagged_example")
    errors.extend(validate_verify(f"{label}.verify", example.get("verify")))
    setup = example.get("setup", "none")
    if setup not in SETUPS:
        errors.append(f"{label}: setup must be one of {', '.join(SETUPS)}")
    has_single = "filename" in example or "code" in example
    if has_single and "files" in example:
        errors.append(f"{label}: use either filename/code or files, not both")
    elif "files" in example:
        errors.extend(
            validate_file_entries(
                f"{label}.files", example["files"], allow_deleted=setup == "git_diff"
            )
        )
    else:
        errors.extend(validate_relative_name(label, example.get("filename")))
        if not isinstance(example.get("code"), str):
            errors.append(f"{label}: needs 'code'")
    if not example.get("language"):
        files = example.get("files")
        if not isinstance(files, list) or not all(
            isinstance(entry, dict) and entry.get("language") for entry in files
        ):
            errors.append(f"{label}: needs 'language'")
    if setup == "git_diff":
        errors.extend(
            validate_file_entries(
                f"{label}.base_files", example.get("base_files"), allow_deleted=False
            )
        )
    elif "base_files" in example:
        errors.append(f"{label}: base_files needs setup: git_diff")
    flags = example.get("scan_flags")
    if flags is not None and (
        not isinstance(flags, list)
        or not all(isinstance(flag, str) and flag.startswith("-") for flag in flags)
    ):
        errors.append(f"{label}: scan_flags must be a list of CLI options")
    if "expect_line" in example:
        line = example["expect_line"]
        if key.endswith("not_flagged_example"):
            errors.append(f"{label}: expect_line only applies to flagged examples")
        elif not isinstance(line, int) or line < 1:
            errors.append(f"{label}: expect_line must be a positive line number")
    if "expect_file" in example:
        names = [entry["filename"] for entry in example_files(example)]
        if example["expect_file"] not in names:
            errors.append(f"{label}: expect_file is not one of the example's files")
    return errors


def validate_verify(label, value) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict) or set(value) - {"mode", "reason"}:
        return [f"{label}: expected {{mode: manual, reason: ...}}"]
    if value.get("mode") != "manual":
        return [f"{label}: mode must be 'manual' (automatic checks are the default)"]
    if not isinstance(value.get("reason"), str) or not value["reason"].strip():
        return [f"{label}: a manual example needs a reason"]
    return []


def validate_gate(where, gate) -> list[str]:
    label = f"{where}: gate"
    if not isinstance(gate, dict):
        return [f"{label}: expected a mapping with at least 'full'"]
    errors = []
    unknown = set(gate) - GATE_KEYS
    if unknown:
        errors.append(f"{label}: unknown key(s) {sorted(unknown)}")
    states = ", ".join(GATE_STATES)
    if gate.get("full") not in GATE_STATES:
        errors.append(f"{label}: full must be one of {states}")
    if "diff" in gate and gate["diff"] not in GATE_STATES:
        errors.append(f"{label}: diff must be one of {states}")
    for key in ("opt_in", "note"):
        if key in gate and (not isinstance(gate[key], str) or not gate[key].strip()):
            errors.append(f"{label}: {key} must be text")
    return errors


def validate_more_examples(where, value) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        return [f"{where}: more_examples must be a non-empty list"]
    errors = []
    for index, pair in enumerate(value):
        label = f"more_examples[{index}]"
        if not isinstance(pair, dict) or set(pair) != MORE_EXAMPLE_KEYS:
            errors.append(f"{where}: {label} needs exactly 'flagged' and 'not_flagged'")
            continue
        errors += validate_example(where, f"{label}.flagged_example", pair["flagged"])
        errors += validate_example(
            where, f"{label}.not_flagged_example", pair["not_flagged"]
        )
        if isinstance(pair["not_flagged"], dict) and not pair["not_flagged"].get("why"):
            errors.append(f"{where}: {label}.not_flagged needs 'why'")
    return errors


def validate_suppress_checks(where, data) -> list[str]:
    suppress = data["false_alarms_and_suppression"].get("suppress") or []
    errors = []
    for index, item in enumerate(suppress):
        if not isinstance(item, dict) or "check" not in item:
            continue
        label = f"{where}: false_alarms_and_suppression.suppress[{index}].check"
        check = normalize_check(item["check"])
        if check is None:
            errors.append(f"{label}: use one of {', '.join(CHECK_KINDS)} or a mapping")
            continue
        if check["kind"] not in CHECK_KINDS:
            errors.append(f"{label}: kind must be one of {', '.join(CHECK_KINDS)}")
        if check["expect"] not in CHECK_EXPECTS:
            errors.append(f"{label}: expect must be one of {', '.join(CHECK_EXPECTS)}")
        if check["kind"] == "example":
            errors += validate_example(label, "check.example", check.get("example"))
            continue
        flagged = data["flagged_example"]
        if check["kind"] == "inline":
            errors += inline_check_problems(label, flagged)
        if check["kind"] == "baseline" and flagged.get("setup", "none") == "git_diff":
            errors.append(
                f"{label}: baseline checks need a flagged example without git_diff"
            )
        if check["kind"] == "config":
            names = {entry["filename"] for entry in example_files(flagged)}
            names |= {entry["filename"] for entry in flagged.get("base_files") or []}
            if "pyproject.toml" in names:
                errors.append(
                    f"{label}: the flagged example already has a pyproject.toml"
                )
    return errors


def normalize_check(value) -> dict | None:
    if isinstance(value, str):
        return {"kind": value, "expect": "hidden"}
    if not isinstance(value, dict) or set(value) - {"kind", "expect", "example"}:
        return None
    check = dict(value)
    check.setdefault("expect", "hidden")
    return check


def comment_prefix(language: str | None) -> str:
    name = str(language or "").lower()
    if name in HASH_COMMENT_LANGUAGES:
        return "#"
    if name in SLASH_COMMENT_LANGUAGES:
        return "//"
    return ""


def inline_check_problems(label, flagged) -> list[str]:
    if not flagged.get("expect_line"):
        return [f"{label}: an inline check needs expect_line on the flagged example"]
    target_file = flagged.get("expect_file") or example_files(flagged)[0]["filename"]
    for entry in example_files(flagged):
        language = entry.get("language")
        if entry["filename"] == target_file and not comment_prefix(language):
            hint = "use check: {kind: example, ...}"
            return [f"{label}: no line-comment syntax known for {language}; {hint}"]
    return []


def validate_fix(where, fix) -> list[str]:
    label = f"{where}: fix"
    if not isinstance(fix, dict):
        return [f"{label}: expected a mapping"]
    errors = []
    unknown = set(fix) - FIX_KEYS
    if unknown:
        errors.append(f"{label}: unknown key(s) {sorted(unknown)}")
    if not isinstance(fix.get("explanation"), str) or not fix["explanation"].strip():
        errors.append(f"{label}: needs 'explanation'")
    if "code" in fix and not isinstance(fix["code"], str):
        errors.append(f"{label}: code must be text")
    if "filename" in fix:
        errors.extend(validate_relative_name(label, fix["filename"]))
        if not isinstance(fix.get("code"), str):
            errors.append(f"{label}: a fix with a filename needs code")
    return errors


def validate_false_alarms(where, value) -> list[str]:
    label = f"{where}: false_alarms_and_suppression"
    if not isinstance(value, dict):
        return [f"{label}: expected a mapping with misfires and suppress"]
    errors = []
    unknown = set(value) - FALSE_ALARM_KEYS
    if unknown:
        errors.append(f"{label}: unknown key(s) {sorted(unknown)}")
    misfires = value.get("misfires")
    if not isinstance(misfires, list) or not misfires:
        errors.append(f"{label}: misfires must be a non-empty list")
    elif not all(isinstance(item, str) and item.strip() for item in misfires):
        errors.append(f"{label}: misfires must be text")
    suppress = value.get("suppress")
    if not isinstance(suppress, list) or not suppress:
        errors.append(f"{label}: suppress must be a non-empty list")
        return errors
    for index, item in enumerate(suppress):
        item_label = f"{label}.suppress[{index}]"
        if not isinstance(item, dict) or not item.get("text"):
            errors.append(f"{item_label}: needs 'text'")
            continue
        unknown = set(item) - SUPPRESS_KEYS
        if unknown:
            errors.append(f"{item_label}: unknown key(s) {sorted(unknown)}")
    return errors


def code_width_warnings(where, data) -> list[str]:
    warnings = []
    blocks = []
    for key in ("flagged_example", "not_flagged_example"):
        for entry in example_files(data[key]):
            blocks.append((f"{key} {entry['filename']}", entry.get("code") or ""))
        for entry in data[key].get("base_files") or []:
            blocks.append((f"{key} base {entry['filename']}", entry.get("code") or ""))
    blocks.append(("fix", data["fix"].get("code") or ""))
    for item in data["false_alarms_and_suppression"].get("suppress") or []:
        blocks.append(("suppress", item.get("code") or ""))
    for label, code in blocks:
        for number, line in enumerate(code.splitlines(), start=1):
            if len(line) > MAX_CODE_COLUMNS:
                warnings.append(
                    f"{where}: {label} line {number} is {len(line)} columns "
                    f"(over {MAX_CODE_COLUMNS} wraps in print)"
                )
    return warnings


DATA_FILE_LANGUAGES = {
    ".toml": "toml",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".md": "markdown",
    ".cfg": "ini",
    ".ini": "ini",
    ".txt": "text",
}


def example_files(example: dict) -> list[dict]:
    if "files" in example:
        files = []
        for entry in example["files"]:
            files.append(
                {
                    "filename": entry["filename"],
                    "code": entry.get("code") or "",
                    "language": entry.get("language") or example.get("language"),
                    "deleted": bool(entry.get("deleted")),
                }
            )
        return files
    return [
        {
            "filename": example["filename"],
            "code": example["code"],
            "language": example.get("language"),
            "deleted": False,
        }
    ]


def load_pending(catalog: dict[str, dict]) -> dict[str, str]:
    """Rules allowed to have no page yet, with the reason."""
    if not PENDING_FILE.is_file():
        return {}
    data = read_yaml(PENDING_FILE)
    entries = (data or {}).get("pending")
    if not isinstance(entries, dict):
        raise BuildError(f"{PENDING_FILE.name}: expected a 'pending' mapping")
    pending = {}
    for rule_id, entry in entries.items():
        reason = ""
        if isinstance(entry, dict):
            reason = str(entry.get("reason") or "").strip()
        if not reason:
            raise BuildError(f"{PENDING_FILE.name}: {rule_id} needs a reason")
        if rule_id not in catalog:
            raise BuildError(f"{PENDING_FILE.name}: {rule_id} is not in the catalog")
        pending[rule_id] = reason
    return pending


def build_coverage(catalog, families, pages, pending=None) -> dict:
    aliases = catalog_aliases(catalog)
    by_family = {family["id"]: {"written": [], "missing": []} for family in families}
    for rule_id, entry in catalog.items():
        if rule_id in aliases:
            continue
        family_id = family_for_rule(entry, families)
        if rule_id in pages:
            family_id = pages[rule_id]["family"]
            by_family[family_id]["written"].append(rule_id)
        else:
            by_family[family_id]["missing"].append(rule_id)
    missing = sum(len(item["missing"]) for item in by_family.values())
    pending = pending or {}
    missing_ids = [
        rule_id for item in by_family.values() for rule_id in item["missing"]
    ]
    manual = {}
    for rule_id, page in pages.items():
        reasons = sorted(
            {item["manual"] for item in verification_targets(page) if item["manual"]}
        )
        if reasons:
            manual[rule_id] = reasons
    return {
        "unaccounted": sorted(
            rule_id for rule_id in missing_ids if rule_id not in pending
        ),
        "pending_written": sorted(rule_id for rule_id in pending if rule_id in pages),
        "pending": pending,
        "manual": manual,
        "total": len(catalog),
        "pages_needed": len(catalog) - len(aliases),
        "written": len(pages),
        "missing": missing,
        "families": families,
        "by_family": by_family,
        "catalog": catalog,
        "remapped": aliases,
        "pages": pages,
    }


def render_coverage(coverage) -> str:
    lines = [
        "# Skylos rule handbook coverage",
        "",
        (
            f"Generated {datetime.date.today().isoformat()} from "
            f"skylos/rules/catalog.py (Skylos {skylos_version()})."
        ),
        "",
        (
            f"Catalog IDs: {coverage['total']}, of which {len(coverage['remapped'])} "
            f"are reported under another rule's ID, so {coverage['pages_needed']} "
            f"rules need a page. Written: {coverage['written']}. "
            f"Not yet written: {coverage['missing']}."
        ),
        "",
        "| Family | Rules | Written | Not yet written |",
        "|:--|--:|--:|--:|",
    ]
    for family in coverage["families"]:
        counts = coverage["by_family"][family["id"]]
        total = len(counts["written"]) + len(counts["missing"])
        lines.append(
            f"| {family['title']} | {total} | {len(counts['written'])} | "
            f"{len(counts['missing'])} |"
        )
    manual = coverage["manual"]
    lines += [
        "",
        f"Pages with examples that are not machine-checked: {len(manual)}.",
    ]
    for rule_id, reasons in sorted(manual.items()):
        lines.append(f"- {rule_id}: {'; '.join(reasons)}")
    if coverage["unaccounted"]:
        lines += [
            "",
            "## Missing from pending.yaml",
            "",
            "These rules have no page and no pending entry; the build fails until",
            "each gets one or the other.",
            "",
        ]
        lines += [f"- {rule_id}" for rule_id in coverage["unaccounted"]]
    if coverage["pending_written"]:
        lines += ["", "## Written but still in pending.yaml (remove the entry)", ""]
        lines += [f"- {rule_id}" for rule_id in coverage["pending_written"]]
    lines += ["", "## Not yet written", ""]
    for family in coverage["families"]:
        missing = sorted(coverage["by_family"][family["id"]]["missing"])
        if not missing:
            continue
        lines += [f"### {family['title']} ({len(missing)})", ""]
        for rule_id in missing:
            entry = coverage["catalog"][rule_id]
            lines.append(f"- {rule_id} {entry['name']}")
        lines.append("")
    if coverage["remapped"]:
        lines += [
            "## Catalog IDs reported under another ID",
            "",
            "The Go engine emits these IDs, but Skylos reports them under the",
            "cross-language rule (skylos/visitors/languages/go/go.py).",
            "",
        ]
        for rule_id, target in sorted(coverage["remapped"].items()):
            status = "target not yet written"
            if target in coverage["pages"]:
                status = "described on its page"
            lines.append(f"- {rule_id} -> {target} ({status})")
        lines.append("")
    return "\n".join(lines)


def rule_scan_flags(rule_id: str) -> list[str]:
    from skylos.cli import _apply_selected_rule_analysis_flags

    args = argparse.Namespace(
        select=[rule_id],
        danger=False,
        ai_defects=False,
        quality=False,
        secrets=False,
        sca=False,
        scan_publisher_changes=False,
    )
    _apply_selected_rule_analysis_flags(args)
    flags = []
    for attribute, flag in (
        ("danger", "--danger"),
        ("secrets", "--secrets"),
        ("quality", "--quality"),
        ("ai_defects", "--ai-defects"),
        ("sca", "--sca"),
        ("scan_publisher_changes", "--scan-publisher-changes"),
    ):
        if getattr(args, attribute):
            flags.append(flag)
    return flags


def example_scan_flags(rule_id: str, example: dict) -> list[str]:
    if example.get("scan_flags") is not None:
        return list(example["scan_flags"])
    flags = rule_scan_flags(rule_id)
    if example.get("setup") == "git_diff":
        flags += ["--diff", "HEAD"]
    return flags


def example_digest(rule_id: str, kind: str, example: dict, flags: list[str]) -> str:
    payload = json.dumps(
        {"rule": rule_id, "kind": kind, "example": example, "flags": flags},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verification_targets(page: dict) -> list[dict]:
    """Every check the page makes: its examples, its fix, extra language
    pairs and suppression checks, each with what Skylos must do."""
    targets = [
        target("flagged", page["flagged_example"], True),
        target("not_flagged", page["not_flagged_example"], False),
    ]
    fix = page["fix"]
    if fix.get("filename"):
        fix_example = fix_check_example(page["flagged_example"], fix)
        if fix.get("scan_flags") is not None:
            fix_example["scan_flags"] = fix["scan_flags"]
        targets.append(target("fix", fix_example, False))
    for index, pair in enumerate(page.get("more_examples") or []):
        targets.append(target(f"more{index}-flagged", pair["flagged"], True))
        targets.append(target(f"more{index}-not_flagged", pair["not_flagged"], False))
    targets += suppress_targets(page)
    page_manual = (page.get("verify") or {}).get("reason")
    for item in targets:
        manual = (item["example"].get("verify") or {}).get("reason")
        if page_manual:
            manual = page_manual
        item["manual"] = manual or ""
    return targets


def fix_check_example(flagged: dict, fix: dict) -> dict:
    language = fix.get("language") or flagged.get("language")
    fixed = {"filename": fix["filename"], "code": fix["code"], "language": language}
    if "files" not in flagged:
        return {"language": language, "filename": fix["filename"], "code": fix["code"]}
    files = []
    replaced = False
    for entry in flagged["files"]:
        if entry["filename"] == fix["filename"]:
            files.append(fixed)
            replaced = True
            continue
        files.append(entry)
    if not replaced:
        files.append(fixed)
    example = {"language": flagged.get("language"), "files": files}
    for key in ("setup", "base_files"):
        if key in flagged:
            example[key] = flagged[key]
    return example


def target(kind: str, example: dict, should_flag: bool, baseline: bool = False) -> dict:
    return {
        "kind": kind,
        "example": example,
        "should_flag": should_flag,
        "baseline": baseline,
        "manual": "",
    }


def suppress_targets(page: dict) -> list[dict]:
    targets = []
    suppress = page["false_alarms_and_suppression"].get("suppress") or []
    for index, item in enumerate(suppress):
        if "check" not in item:
            continue
        check = normalize_check(item["check"])
        should_flag = check["expect"] == "reported"
        kind = f"suppress{index}"
        if check["kind"] == "example":
            targets.append(target(kind, check["example"], should_flag))
            continue
        flagged = page["flagged_example"]
        if check["kind"] == "inline":
            example = with_inline_marker(flagged, page["id"])
        elif check["kind"] == "config":
            example = with_extra_file(
                flagged, "pyproject.toml", f'[tool.skylos]\nignore = ["{page["id"]}"]\n'
            )
        else:
            example = flagged
        targets.append(
            target(kind, example, should_flag, baseline=check["kind"] == "baseline")
        )
    return targets


def with_inline_marker(example: dict, rule_id: str) -> dict:
    expected = example.get("expect_file") or example_files(example)[0]["filename"]
    files = []
    for entry in example_files(example):
        entry = dict(entry)
        if entry["filename"] == expected:
            lines = entry["code"].split("\n")
            index = example["expect_line"] - 1
            prefix = comment_prefix(entry.get("language"))
            marker = f"{prefix} skylos: ignore[{rule_id}] {CHECK_MARKER_REASON}"
            lines[index] = f"{lines[index]}  {marker}"
            entry["code"] = "\n".join(lines)
        files.append(entry)
    return replace_files(example, files)


def with_extra_file(example: dict, filename: str, code: str) -> dict:
    files = [dict(entry) for entry in example_files(example)]
    files.append({"filename": filename, "code": code, "language": "toml"})
    return replace_files(example, files)


def replace_files(example: dict, files: list[dict]) -> dict:
    derived = {
        key: value
        for key, value in example.items()
        if key not in {"filename", "code", "files", "why"}
    }
    derived["files"] = [
        {key: value for key, value in entry.items() if value is not None}
        for entry in files
    ]
    derived.setdefault("expect_file", files[0]["filename"])
    return derived


def resolve_skylos(explicit: str | None) -> list[str]:
    if explicit:
        return [explicit]
    beside = Path(sys.executable).parent / "skylos"
    if beside.is_file():
        return [str(beside)]
    found = shutil.which("skylos")
    if found:
        return [found]
    raise BuildError("no skylos executable found; pass --skylos")


def verification_env(home: Path) -> dict[str, str]:
    env = {}
    for key in VERIFY_ENV_KEEP:
        if os.environ.get(key):
            env[key] = os.environ[key]
    python_path = [str(REPO_ROOT)]
    if os.environ.get("PYTHONPATH"):
        python_path.append(os.environ["PYTHONPATH"])
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "PYTHONPATH": os.pathsep.join(python_path),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SKYLOS_NO_CLIPBOARD": "1",
            "SKYLOS_CUSTOM_RULES": "[]",
            "NO_COLOR": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Handbook",
            "GIT_AUTHOR_EMAIL": "handbook@example.invalid",
            "GIT_COMMITTER_NAME": "Handbook",
            "GIT_COMMITTER_EMAIL": "handbook@example.invalid",
        }
    )
    return env


def contained_path(base: Path, *parts: str) -> Path:
    """`base/parts`, refused when it would leave `base` or is a symlink."""
    resolved_base = base.resolve()
    target = resolved_base.joinpath(*parts)
    resolved = target.resolve()
    if not resolved.is_relative_to(resolved_base) or target.is_symlink():
        raise BuildError(f"refusing to use {target}: outside {resolved_base}")
    return resolved


def write_files(root: Path, entries: list[dict]) -> None:
    for entry in entries:
        target = contained_path(root, entry["filename"])
        if entry.get("deleted"):
            if target.exists():
                target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(  # skylos: ignore[SKY-D324] contained_path keeps it in the fresh example folder
            entry["code"], encoding="utf-8"
        )


def run_git(root: Path, env: dict, *args: str) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BuildError(
            f"git {' '.join(args)} failed in {root}: {result.stderr.strip()}"
        )


def prepare_example(root: Path, example: dict, env: dict) -> None:
    root.mkdir(parents=True, exist_ok=False)
    setup = example.get("setup", "none")
    if setup == "none":
        write_files(root, example_files(example))
        return
    run_git(root, env, "init", "--quiet", "--initial-branch=main")
    if setup == "git_diff":
        base_entries = []
        for entry in example["base_files"]:
            base_entries.append({"filename": entry["filename"], "code": entry["code"]})
        write_files(root, base_entries)
        run_git(root, env, "add", "--all")
        run_git(root, env, "commit", "--quiet", "--no-verify", "-m", "base")
        write_files(root, example_files(example))
        return
    write_files(root, example_files(example))
    run_git(root, env, "add", "--all")
    run_git(root, env, "commit", "--quiet", "--no-verify", "-m", "example")


def finding_locations(result: dict, root: Path) -> list[dict]:
    from skylos.cli import _RULE_SELECTION_FINDING_CATEGORIES, _finding_rule_id

    locations = []
    for category in _RULE_SELECTION_FINDING_CATEGORIES:
        for item in result.get(category) or []:
            rule_id = _finding_rule_id(item, category)
            if not rule_id:
                continue
            locations.append(
                {
                    "rule_id": rule_id.upper(),
                    "file": relative_file(item, root),
                    "line": finding_line(item),
                }
            )
    metrics = result.get("architecture_metrics") or {}
    for item in metrics.get("advisories") or []:
        rule_id = _finding_rule_id(item, "quality")
        if rule_id:
            locations.append(
                {
                    "rule_id": rule_id.upper(),
                    "file": relative_file(item, root),
                    "line": finding_line(item),
                }
            )
    return locations


def relative_file(item: dict, root: Path) -> str:
    raw = str(item.get("file") or item.get("file_path") or "")
    if not raw:
        return ""
    path = Path(raw)
    if not path.is_absolute():
        return path.as_posix()
    for base in (root.resolve(), root):
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            continue
    return path.as_posix()


def finding_line(item: dict) -> int | None:
    for key in ("line", "line_number", "lineno"):
        value = item.get(key)
        if isinstance(value, int):
            return value
    return None


def verify_pages(pages: dict, args) -> dict:
    scratch = args.scratch
    created = scratch is None
    if created:
        scratch = Path(tempfile.mkdtemp(prefix="skylos-handbook-verify-"))
    scratch = scratch.expanduser().resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    home = scratch / "home"
    home.mkdir(exist_ok=True)
    env = verification_env(home)
    command = resolve_skylos(args.skylos)
    version, module = probe_skylos(command, env, scratch)
    print(f"verify: {' '.join(command)} (skylos {version}, module {module})")
    checks = []
    try:
        for rule_id in sorted(pages):
            for item in verification_targets(pages[rule_id]):
                if item["manual"]:
                    checks.append(manual_check(rule_id, item))
                    continue
                checks.append(verify_example(rule_id, item, scratch, env, command))
    finally:
        if created and not args.keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    failed = len([check for check in checks if not check["passed"]])
    manual = len([check for check in checks if check.get("status") == "manual"])
    return {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "skylos_version": version,
        "skylos_module": module,
        "command": command,
        "scratch": str(scratch),
        "checks": checks,
        "passed": len(checks) - failed - manual,
        "failed": failed,
        "manual": manual,
    }


def expected_text(should_flag: bool) -> str:
    if should_flag:
        return "reported"
    return "not reported"


def manual_check(rule_id: str, item: dict) -> dict:
    flags = example_scan_flags(rule_id, item["example"])
    return {
        "rule_id": rule_id,
        "example": item["kind"],
        "expected": expected_text(item["should_flag"]),
        "flags": flags,
        "status": "manual",
        "reason": item["manual"],
        "actual": "not machine-checked",
        "exit_code": None,
        "passed": True,
        "digest": example_digest(rule_id, item["kind"], item["example"], flags),
    }


def probe_skylos(command, env, scratch) -> tuple[str, str]:
    version = subprocess.run(
        [*command, "--version"],
        cwd=scratch,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    module = subprocess.run(
        [
            sys.executable,
            "-c",
            "import skylos, sys; sys.stdout.write(skylos.__file__)",
        ],
        cwd=scratch,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    version_text = (version.stdout or version.stderr).strip().replace("skylos ", "")
    return version_text, module.stdout.strip()


def verify_example(rule_id, item, scratch, env, command):
    kind = item["kind"]
    example = item["example"]
    should_flag = item["should_flag"]
    flags = example_scan_flags(rule_id, example)
    if item["baseline"]:
        flags = [*flags, "--baseline"]
    root = contained_path(scratch, rule_id, kind)
    output = contained_path(scratch, rule_id, f"{kind}.json")
    result = run_example_scan(
        root, output, example, flags, env, command, item["baseline"]
    )
    check = {
        "rule_id": rule_id,
        "example": kind,
        "expected": expected_text(should_flag),
        "flags": flags,
        "setup": example.get("setup", "none"),
        "exit_code": result.returncode,
        "status": "checked",
        "digest": example_digest(rule_id, kind, example, flags),
    }
    data, problem = read_scan_output(output)
    if problem:
        detail = (result.stderr or result.stdout).strip()[-800:]
        check.update({"actual": problem, "passed": False, "detail": detail})
        return check
    locations = finding_locations(data, root)
    hits = [item for item in locations if item["rule_id"] == rule_id]
    check["hits"] = hits
    check["other_rules"] = sorted({item["rule_id"] for item in locations} - {rule_id})
    check["actual"] = describe_hits(hits)
    errors = data.get("analysis_errors") or []
    if result.returncode == 2 or errors:
        check["analysis_errors"] = len(errors)
    passed = result.returncode in (0, 1) and not errors
    if errors:
        check["detail"] = f"{len(errors)} file(s) or check(s) were not analysed"
    if should_flag:
        wanted, expected_place = expected_hits(example, hits)
        passed = passed and bool(wanted)
        if hits and not wanted:
            check["detail"] = f"expected {expected_place}"
    else:
        passed = passed and not hits
    if result.returncode not in (0, 1):
        check["detail"] = (result.stderr or "").strip()[-800:]
    check["passed"] = passed
    return check


def run_example_scan(root, output, example, flags, env, command, baseline=False):
    if root.exists():
        shutil.rmtree(root)  # skylos: ignore[SKY-D215] contained_path under scratch
    prepare_example(root, example, env)
    if output.exists():
        output.unlink()
    if baseline:
        made = subprocess.run(
            [*command, "baseline", "."],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT_SECONDS,
            check=False,
        )
        if made.returncode != 0:
            return made
    argv = [*command, ".", *flags, "--no-upload", "--format", "json"]
    argv += ["--output", str(output)]
    return subprocess.run(
        argv,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=VERIFY_TIMEOUT_SECONDS,
        check=False,
    )


def read_scan_output(output: Path) -> tuple[dict, str]:
    if not output.is_file():
        return {}, "no JSON output"
    try:
        return json.loads(output.read_text(encoding="utf-8")), ""
    except json.JSONDecodeError as exc:
        return {}, f"unreadable JSON ({exc})"


def describe_hits(hits: list[dict]) -> str:
    if not hits:
        return "not reported"
    return "reported at " + ", ".join(f"{hit['file']}:{hit['line']}" for hit in hits)


def expected_hits(example: dict, hits: list[dict]) -> tuple[list[dict], str]:
    expected_file = example.get("expect_file")
    expected_line = example.get("expect_line")
    if expected_file is None and expected_line:
        expected_file = example_files(example)[0]["filename"]
    wanted = hits
    if expected_file:
        wanted = [hit for hit in wanted if hit["file"] == expected_file]
    if expected_line:
        wanted = [hit for hit in wanted if hit["line"] == expected_line]
    return wanted, f"{expected_file}:{expected_line}"


def print_verify_table(report: dict) -> None:
    print()
    print(f"{'rule':<15} {'example':<20} {'expected':<13} {'result':<7} actual")
    for check in report["checks"]:
        status = "pass"
        if not check["passed"]:
            status = "FAIL"
        if check.get("status") == "manual":
            status = "manual"
            detail = check["reason"]
        else:
            flags = " ".join(check["flags"]) or "(none)"
            detail = f"exit {check['exit_code']}, flags {flags}"
        print(
            f"{check['rule_id']:<15} {check['example']:<20} {check['expected']:<13} "
            f"{status:<7} {check['actual']} ({detail})"
        )
        if check.get("detail"):
            print(f"{'':<58}{check['detail']}")
    print(
        f"\n{report['passed']} passed, {report['failed']} failed, "
        f"{report.get('manual', 0)} not machine-checked"
    )


def read_verify_report(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    checks = {}
    for check in data.get("checks") or []:
        if check.get("passed") and check.get("status") != "manual":
            checks[check["digest"]] = check
    return {
        "version": data.get("skylos_version"),
        "generated": data.get("generated"),
        "checks": checks,
    }


def load_intro(catalog, families, pages) -> list[dict]:
    chapters = []
    for path in sorted(INTRO_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        match = re.match(r"#\s+(.+)\n", text)
        if not match:
            raise BuildError(f"intro/{path.name}: must start with '# Title'")
        body = text[match.end() :]
        slug = re.sub(r"^[0-9]+-", "", path.stem)
        chapters.append(
            {"slug": slug, "title": match.group(1).strip(), "body": body, "path": path}
        )
    if not chapters:
        raise BuildError(f"no front matter in {INTRO_DIR}")
    return chapters


def load_cloud_chapters() -> list[dict]:
    chapters = []
    for path in sorted(CLOUD_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        match = re.match(r"#\s+(.+)\n", text)
        if not match:
            raise BuildError(f"cloud/{path.name}: must start with '# Title'")
        body = text[match.end() :]
        slug = re.sub(r"^[0-9]+-", "", path.stem)
        chapters.append(
            {
                "slug": slug,
                "title": match.group(1).strip(),
                "body": body,
                "path": path,
                "prefix": "cloud",
            }
        )
    return chapters


def chapter_headings(body: str) -> set[str]:
    headings = set()
    in_code = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        match = re.match(r"#{2,4}\s+(.+)", stripped)
        if match:
            headings.add(match.group(1).strip())
    return headings


def chapter_images(body: str) -> list[str]:
    images = []
    for line in body.splitlines():
        match = IMAGE_PATTERN.match(line.strip())
        if match:
            images.append(match.group(2))
    return images


def resolve_image(source: str) -> Path:
    path = (HANDBOOK_DIR / source).resolve()
    if not path.is_relative_to(IMAGE_DIR.resolve()):
        raise BuildError(f"image {source} must live under docs/handbook/img/")
    if path.suffix.lower() not in IMAGE_TYPES:
        raise BuildError(f"image {source} must be a PNG or JPEG file")
    if not path.is_file():
        raise BuildError(f"image {source} does not exist")
    return path


def image_size(data: bytes) -> tuple[int, int] | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    return None


def shot_width_mm(size: tuple[int, int] | None) -> float:
    if not size:
        return SHOT_MAX_WIDTH_MM
    width, height = size
    natural = width * SHOT_MM_PER_PIXEL
    by_height = SHOT_MAX_HEIGHT_MM * width / height
    return round(min(SHOT_MAX_WIDTH_MM, natural, by_height), 1)


def load_cloud_manifest() -> dict:
    if not CLOUD_MANIFEST_FILE.is_file():
        return {}
    data = read_yaml(CLOUD_MANIFEST_FILE)
    if not isinstance(data, dict):
        raise BuildError("cloud/manifest.yaml must be a mapping")
    return data


def cloud_verified_text(manifest: dict) -> str:
    verified = manifest.get("verified_against") or {}
    commit = str(verified.get("commit") or "").strip()
    date_text = str(verified.get("date") or "").strip()
    if not commit or not date_text:
        raise BuildError("cloud/manifest.yaml needs verified_against.commit and .date")
    day = datetime.date.fromisoformat(date_text)
    return f"Verified against Skylos Cloud {commit}, {day.day} {day.strftime('%B %Y')}."


def cloud_problems() -> list[str]:
    chapters = load_cloud_chapters()
    manifest = load_cloud_manifest()
    problems = []
    if not chapters and not manifest:
        return problems
    if not manifest:
        return ["cloud/manifest.yaml is missing"]
    try:
        cloud_verified_text(manifest)
    except (BuildError, ValueError) as error:
        problems.append(f"cloud/manifest.yaml: {error}")
    headings = {
        chapter["path"].name: chapter_headings(chapter["body"]) for chapter in chapters
    }
    for chapter in chapters:
        for source in chapter_images(chapter["body"]):
            try:
                resolve_image(source)
            except BuildError as error:
                problems.append(f"cloud/{chapter['path'].name}: {error}")
    features = manifest.get("features")
    if not isinstance(features, list) or not features:
        problems.append("cloud/manifest.yaml: features must be a non-empty list")
        return problems
    seen = set()
    for feature in features:
        problems.extend(cloud_feature_problems(feature, headings, seen))
    return problems


def cloud_feature_problems(feature, headings, seen) -> list[str]:
    if not isinstance(feature, dict) or not str(feature.get("id") or "").strip():
        return ["cloud/manifest.yaml: every feature needs an id"]
    feature_id = str(feature["id"])
    where = f"cloud/manifest.yaml: {feature_id}"
    problems = []
    if feature_id in seen:
        problems.append(f"{where}: listed twice")
    seen.add(feature_id)
    if not str(feature.get("label") or "").strip():
        problems.append(f"{where}: needs the label shown in Cloud")
    status = feature.get("status", "covered")
    if status not in CLOUD_STATUSES:
        problems.append(f"{where}: status must be one of {', '.join(CLOUD_STATUSES)}")
        return problems
    if status == "not_available" and not str(feature.get("reason") or "").strip():
        problems.append(f"{where}: a feature that is not available needs a reason")
    chapter = str(feature.get("chapter") or "")
    section = str(feature.get("section") or "")
    if not chapter or not section:
        problems.append(f"{where}: has no guide section (chapter and section)")
        return problems
    if chapter not in headings:
        problems.append(f"{where}: chapter {chapter} does not exist in cloud/")
        return problems
    if section not in headings[chapter]:
        problems.append(f"{where}: {chapter} has no section '{section}'")
    return problems


def find_chrome(explicit: str | None) -> str:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend(DEFAULT_CHROME)
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    raise BuildError("Chrome or Chromium not found; pass --chrome or set CHROME_BIN")


def print_pdf(chrome: str, html_path: Path, pdf_path: Path, extra_args=()) -> None:
    with tempfile.TemporaryDirectory(prefix="skylos-handbook-chrome-") as profile:
        if pdf_path.exists():
            pdf_path.unlink()
        command = [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            f"--user-data-dir={profile}",
            "--no-pdf-header-footer",
            "--generate-pdf-document-outline",
            *extra_args,
            f"--print-to-pdf={pdf_path}",
            html_path.as_uri(),
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False
        )
        if pdf_path.is_file() and result.returncode != 0:
            if printed_completely(pdf_path, result.stderr):
                return
        if result.returncode != 0 or not pdf_path.is_file():
            raise BuildError(
                f"Chrome could not print the PDF: {result.stderr.strip()[-600:]}"
            )


def printed_completely(pdf_path: Path, stderr: str) -> bool:
    if "bytes written to file" not in stderr:
        return False
    with pdf_path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(max(0, handle.tell() - 1024))
        tail = handle.read()
    return b"%%EOF" in tail


def pdf_destinations(data: bytes) -> tuple[dict[str, int], int]:
    offsets = pdf_object_offsets(data)

    def body(number: int) -> bytes:
        start = offsets.get(number)
        if start is None:
            raise BuildError(f"PDF object {number} is missing")
        end = data.find(b"endobj", start)
        return data[start:end]

    catalog_number = None
    for number in offsets:
        if re.search(rb"/Type\s*/Catalog\b", body(number)[:4000]):
            catalog_number = number
            break
    if catalog_number is None:
        raise BuildError("PDF has no catalog")
    catalog_body = body(catalog_number)
    pages_ref = re.search(rb"/Pages\s+(\d+)\s+0\s+R", catalog_body)
    if not pages_ref:
        raise BuildError("PDF catalog has no page tree")
    order = []
    stack = [int(pages_ref.group(1))]
    while stack:
        number = stack.pop()
        node = body(number)
        kids = re.search(rb"/Kids\s*\[([^\]]*)\]", node)
        if kids and re.search(rb"/Type\s*/Pages\b", node):
            references = [
                int(value) for value in re.findall(rb"(\d+)\s+0\s+R", kids.group(1))
            ]
            stack.extend(reversed(references))
        else:
            order.append(number)
    page_index = {number: index + 1 for index, number in enumerate(order)}
    destinations = {}
    dests_ref = re.search(rb"/Dests\s+(\d+)\s+0\s+R", catalog_body)
    if dests_ref:
        for name, page in re.findall(
            rb"/([^\s/\[\]<>()]+)\s*\[\s*(\d+)\s+0\s+R", body(int(dests_ref.group(1)))
        ):
            decoded = re.sub(
                rb"#([0-9A-Fa-f]{2})",
                lambda match: bytes([int(match.group(1), 16)]),
                name,
            ).decode("utf-8", errors="replace")
            if int(page) in page_index:
                destinations[decoded] = page_index[int(page)]
    return destinations, len(order)


def pdf_object_offsets(data: bytes) -> dict[int, int]:
    start = data.rfind(b"startxref")
    match = re.match(rb"startxref\s+(\d+)", data[start:])
    if start < 0 or not match:
        raise BuildError("PDF has no cross-reference table")
    position = int(match.group(1))
    if not data.startswith(b"xref", position):
        raise BuildError("PDF uses a cross-reference stream; cannot read page numbers")
    offsets = {}
    cursor = position + len(b"xref")
    section = re.compile(rb"\s*(\d+)\s+(\d+)\s*\r?\n")
    entry = re.compile(rb"(\d{10}) (\d{5}) ([nf])\s*\r?\n?")
    while True:
        header = section.match(data, cursor)
        if not header:
            break
        first, count = int(header.group(1)), int(header.group(2))
        cursor = header.end()
        for index in range(count):
            row = entry.match(data, cursor)
            if not row:
                raise BuildError("PDF cross-reference table is malformed")
            cursor = row.end()
            if row.group(3) == b"n":
                offsets[first + index] = int(row.group(1))
    return offsets


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def rule_anchor(rule_id: str) -> str:
    return "rule-" + slug(rule_id)


def language_name(language: str | None) -> str:
    if not language:
        return ""
    return LANGUAGE_NAMES.get(language.lower(), language)


class Book:
    def __init__(self, catalog, families, pages, intro, verify_report, mode):
        self.catalog = catalog
        self.families = families
        self.pages = pages
        self.intro = intro
        self.cloud: list[dict] = []
        self.cloud_manifest: dict = {}
        self.verify_report = verify_report
        self.mode = mode
        self.version = skylos_version()
        self.formatter_css = HtmlFormatter(style="default").get_style_defs(".code")
        self.anchors: list[str] = []
        self.page_numbers: dict[str, int] = {}
        self.rules_by_family = {family["id"]: [] for family in families}
        for rule_id in sorted(pages):
            self.rules_by_family[pages[rule_id]["family"]].append(rule_id)
        self.reference_data: dict | None = None
        self.aliases = catalog_aliases(catalog)
        self.page_rule_count = len(catalog) - len(self.aliases)
        self.aliases_by_target: dict[str, list[str]] = {}
        for alias, target in sorted(self.aliases.items()):
            self.aliases_by_target.setdefault(target, []).append(alias)

    def family_rule_count(self, family_id: str) -> int:
        count = 0
        for rule_id, entry in self.catalog.items():
            if rule_id in self.aliases:
                continue
            if family_for_rule(entry, self.families) == family_id:
                count += 1
        return count

    def render(self, page_numbers: dict[str, int]) -> str:
        self.page_numbers = page_numbers
        self.anchors = []
        body = [self.render_cover(), self.render_contents()]
        for number, chapter in enumerate(self.intro, start=1):
            body.append(self.render_chapter(number, chapter))
        for number, chapter in enumerate(self.cloud, start=len(self.intro) + 1):
            body.append(self.render_chapter(number, chapter))
        for family in self.active_families():
            body.append(self.render_family(family))
            for rule_id in self.rules_by_family[family["id"]]:
                body.append(self.render_rule(self.pages[rule_id]))
        body.append(self.render_command_appendix())
        body.append(self.render_index())
        css = CSS_FILE.read_text(encoding="utf-8")
        return (
            '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            "<title>Skylos Rule Handbook</title>\n"
            f"<style>\n{css}\n{self.formatter_css}\n</style>\n</head>\n<body>\n"
            + "\n".join(body)
            + "\n</body>\n</html>\n"
        )

    def active_families(self) -> list[dict]:
        return [
            family for family in self.families if self.rules_by_family[family["id"]]
        ]

    def anchor(self, name: str) -> str:
        self.anchors.append(name)
        return name

    def page_ref(self, target: str) -> str:
        number = self.page_numbers.get(target)
        text = PAGE_NUMBER_PLACEHOLDER
        if number is not None:
            text = str(number)
        return f'<span class="pn">{html.escape(text)}</span>'

    def link_rule_ids(self, escaped: str) -> str:
        def replace(match):
            rule_id = match.group(0)
            label = html.escape(rule_id)
            if rule_id in self.pages:
                anchor = html.escape(rule_anchor(rule_id))
                return f'<a class="rule-link" href="#{anchor}">{label}</a>'
            return f'<span class="rid">{label}</span>'

        return RULE_ID_PATTERN.sub(replace, escaped)

    def inline(self, text: str) -> str:
        spans = []

        def keep_code(match):
            spans.append(f"<code>{html.escape(match.group(1))}</code>")
            return f"\x00{len(spans) - 1}\x00"

        held = re.sub(r"`([^`]+)`", keep_code, str(text).replace("\x00", ""))
        escaped = html.escape(held, quote=False)
        escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
        escaped = re.sub(
            r"\[([^\]]+)\]\(([^)\s]+)\)",
            lambda match: (
                f'<a href="{html.escape(match.group(2))}">{match.group(1)}</a>'
            ),
            escaped,
        )
        escaped = self.link_rule_ids(escaped)
        return re.sub(r"\x00(\d+)\x00", lambda match: spans[int(match.group(1))], escaped)

    def code_block(
        self,
        code: str,
        language: str | None,
        filename: str | None = None,
        highlight_lines=(),
    ):
        lexer = None
        if language:
            name = LEXER_NAMES.get(language.lower(), language.lower())
            try:
                lexer = get_lexer_by_name(name)
            except ClassNotFound:
                lexer = None
        if lexer is None and filename:
            try:
                lexer = get_lexer_for_filename(filename, code)
            except ClassNotFound:
                lexer = None
        if lexer is None:
            lexer = get_lexer_by_name("text")
        formatter = HtmlFormatter(
            style="default",
            cssclass="code",
            linenos="inline",
            hl_lines=list(highlight_lines),
            wrapcode=True,
        )
        return highlight(code.rstrip("\n").expandtabs(4) + "\n", lexer, formatter)

    def plain_code(self, code: str, language: str | None) -> str:
        lexer = get_lexer_by_name("text")
        if language:
            try:
                lexer = get_lexer_by_name(
                    LEXER_NAMES.get(language.lower(), language.lower())
                )
            except ClassNotFound:
                lexer = get_lexer_by_name("text")
        formatter = HtmlFormatter(style="default", cssclass="code", wrapcode=True)
        return highlight(code.rstrip("\n").expandtabs(4) + "\n", lexer, formatter)

    def render_cover(self) -> str:
        total = self.page_rule_count
        written = len(self.pages)
        edition = "Complete edition"
        scope = f"All {total} rules"
        if self.mode == "pilot" and written < total:
            edition = "Edition in progress"
            scope = f"{written} of {total} rules"
        today = datetime.date.today()
        date_text = f"{today.day} {today.strftime('%B %Y')}"
        commit = git_short_head()
        commit_text = ""
        if commit:
            commit_text = f" · source {html.escape(commit)}"
        return (
            '<section class="cover">\n'
            '<div class="cover-band"></div>\n'
            '<div class="cover-body">\n'
            '<p class="cover-kicker">Skylos</p>\n'
            '<h1 class="cover-title">Rule Handbook</h1>\n'
            '<p class="cover-sub">What every rule finds, what the code looks like, '
            "and how Skylos decides.</p>\n"
            "</div>\n"
            '<div class="cover-foot">\n'
            f'<p class="cover-edition">{edition}</p>\n'
            f"<p>{scope} · Skylos {html.escape(self.version)} · {date_text}{commit_text}</p>\n"
            "</div>\n"
            "</section>"
        )

    def render_contents(self) -> str:
        rows = []
        rows.append('<div class="toc-part">Before you start</div>')
        for number, chapter in enumerate(self.intro, start=1):
            target = f"intro-{chapter['slug']}"
            rows.append(
                self.toc_row(
                    f"{number}. {html.escape(chapter['title'])}", target, "toc-chapter"
                )
            )
        if self.cloud:
            rows.append('<div class="toc-part">Using Skylos Cloud</div>')
        for number, chapter in enumerate(self.cloud, start=len(self.intro) + 1):
            target = f"cloud-{chapter['slug']}"
            rows.append(
                self.toc_row(
                    f"{number}. {html.escape(chapter['title'])}", target, "toc-chapter"
                )
            )
        rows.append('<div class="toc-part">Rules</div>')
        for family in self.active_families():
            target = f"family-{family['id']}"
            rows.append(
                self.toc_row(html.escape(family["title"]), target, "toc-family")
            )
            for rule_id in self.rules_by_family[family["id"]]:
                page = self.pages[rule_id]
                label = f'<span class="toc-id">{rule_id}</span> {html.escape(page["title"])}'
                rows.append(self.toc_row(label, rule_anchor(rule_id), "toc-rule"))
        rows.append('<div class="toc-part">Appendix</div>')
        rows.append(
            self.toc_row("Command and flag reference", "commands", "toc-chapter")
        )
        rows.append(self.toc_row("Rule index", "index", "toc-chapter"))
        return (
            '<section class="contents" id="contents">\n'
            '<h1 class="contents-title">Contents</h1>\n'
            + "\n".join(rows)
            + "\n</section>"
        )

    def toc_row(self, label: str, target: str, css_class: str) -> str:
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<a class="toc-row {css_class}" href="#{target}">'
            f'<span class="toc-label">{label}</span>'
            f'<span class="toc-fill"></span>{self.page_ref(target)}</a>'
        )

    def render_chapter(self, number: int, chapter: dict) -> str:
        prefix = chapter.get("prefix", "intro")
        target = self.anchor(f"{prefix}-{chapter['slug']}")
        content = self.markdown(
            self.expand_placeholders(chapter["body"], chapter["path"])
        )
        css_class = "chapter"
        if number == 1:
            css_class = "chapter first"
        if prefix == "cloud":
            css_class = "chapter cloud-guide"
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<section class="{css_class}" id="{target}">\n'
            f'<p class="chapter-number">Chapter {number}</p>\n'
            f"<h1>{self.inline(chapter['title'])}</h1>\n{content}\n</section>"
        )

    def expand_placeholders(self, text: str, path: Path) -> str:
        values = {
            "rule_count": str(len(self.catalog)),
            "page_count": str(self.page_rule_count),
            "alias_count": str(len(self.aliases)),
            "written_count": str(len(self.pages)),
            "skylos_version": self.version,
            "family_table": self.family_table_markdown(),
            "category_table": self.category_table_markdown(),
            "command_overview": self.command_overview_markdown(),
        }
        if self.cloud_manifest:
            values["cloud_verified"] = cloud_verified_text(self.cloud_manifest)

        def replace(match):
            key = match.group(1)
            if key not in values:
                raise BuildError(
                    f"{path.parent.name}/{path.name}: unknown placeholder {{{{{key}}}}}"
                )
            return values[key]

        return PLACEHOLDER_PATTERN.sub(replace, text)

    def family_table_markdown(self) -> str:
        lines = ["| Family | ID prefixes | Rules |", "|:--|:--|--:|"]
        for family in self.families:
            count = self.family_rule_count(family["id"])
            lines.append(f"| {family['title']} | {family['prefixes']} | {count} |")
        return "\n".join(lines)

    def category_table_markdown(self) -> str:
        counts: dict[str, int] = {}
        for entry in self.catalog.values():
            counts[entry["category"]] = counts.get(entry["category"], 0) + 1
        lines = ["| Catalog category | Rules |", "|:--|--:|"]
        for category in sorted(counts, key=lambda name: (-counts[name], name)):
            lines.append(f"| `{category}` | {counts[category]} |")
        return "\n".join(lines)

    def markdown(self, text: str) -> str:
        lines = text.splitlines()
        out = []
        index = 0
        paragraph: list[str] = []

        def flush():
            if paragraph:
                out.append(f"<p>{self.inline(' '.join(paragraph))}</p>")
                paragraph.clear()

        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            if stripped.startswith("```"):
                flush()
                language = stripped[3:].strip() or None
                code = []
                index += 1
                while index < len(lines) and not lines[index].strip().startswith("```"):
                    code.append(lines[index])
                    index += 1
                index += 1
                out.append(self.plain_code("\n".join(code), language))
                continue
            image = IMAGE_PATTERN.match(stripped)
            if image:
                flush()
                out.append(self.image_figure(image.group(1), image.group(2)))
                index += 1
                continue
            heading = re.match(r"(#{2,4})\s+(.+)", stripped)
            if heading:
                flush()
                level = len(heading.group(1))
                out.append(f"<h{level}>{self.inline(heading.group(2))}</h{level}>")
                index += 1
                continue
            if (
                stripped.startswith("|")
                and index + 1 < len(lines)
                and re.match(r"^\|?\s*:?-{2,}", lines[index + 1].strip())
            ):
                flush()
                table_lines = []
                while index < len(lines) and lines[index].strip().startswith("|"):
                    table_lines.append(lines[index].strip())
                    index += 1
                out.append(self.markdown_table(table_lines))
                continue
            if re.match(r"([-*]|\d+\.)\s+", stripped):
                flush()
                ordered = bool(re.match(r"\d+\.\s+", stripped))
                first_number = re.match(r"(\d+)\.", stripped)
                items = []
                while index < len(lines):
                    current = lines[index].strip()
                    item = re.match(r"([-*]|\d+\.)\s+(.*)", current)
                    if item:
                        items.append(item.group(2))
                    elif current and items and lines[index].startswith(("  ", "\t")):
                        items[-1] += " " + current
                    else:
                        break
                    index += 1
                tag = "ul"
                opening = "ul"
                if ordered:
                    tag = "ol"
                    opening = "ol"
                    if first_number and first_number.group(1) != "1":
                        opening = f'ol start="{int(first_number.group(1))}"'
                rendered = "".join(f"<li>{self.inline(item)}</li>" for item in items)
                out.append(f"<{opening}>{rendered}</{tag}>")
                continue
            if stripped.startswith(">"):
                flush()
                quote = []
                while index < len(lines) and lines[index].strip().startswith(">"):
                    quote.append(lines[index].strip()[1:].strip())
                    index += 1
                out.append(f'<div class="note">{self.inline(" ".join(quote))}</div>')
                continue
            if not stripped:
                flush()
                index += 1
                continue
            paragraph.append(stripped)
            index += 1
        flush()
        return "\n".join(out)

    def image_figure(self, caption: str, source: str) -> str:
        path = resolve_image(source)
        raw = path.read_bytes()
        data = base64.b64encode(raw).decode("ascii")
        mime = IMAGE_TYPES[path.suffix.lower()]
        width = shot_width_mm(image_size(raw))
        caption_html = ""
        if caption.strip():
            caption_html = f"<figcaption>{self.inline(caption)}</figcaption>"
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            '<figure class="shot">'
            f'<img src="data:{mime};base64,{data}" style="width:{width}mm" '
            f'alt="{html.escape(caption)}">'
            f"{caption_html}</figure>"
        )

    def markdown_table(self, table_lines: list[str]) -> str:
        def cells(row: str) -> list[str]:
            return [cell.strip() for cell in row.strip().strip("|").split("|")]

        header = cells(table_lines[0])
        aligns = []
        for spec in cells(table_lines[1]):
            align = "left"
            if spec.endswith(":") and spec.startswith(":"):
                align = "center"
            elif spec.endswith(":"):
                align = "right"
            aligns.append(align)
        head = "".join(
            f'<th class="al-{aligns[i]}">{self.inline(cell)}</th>'
            for i, cell in enumerate(header)
        )
        body = []
        for row in table_lines[2:]:
            values = cells(row)
            body.append(
                "<tr>"
                + "".join(
                    f'<td class="al-{aligns[min(i, len(aligns) - 1)]}">{self.inline(cell)}</td>'
                    for i, cell in enumerate(values)
                )
                + "</tr>"
            )
        return f'<table class="grid"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'

    def render_family(self, family: dict) -> str:
        target = self.anchor(f"family-{family['id']}")
        rule_ids = self.rules_by_family[family["id"]]
        total = self.family_rule_count(family["id"])
        rows = []
        for rule_id in rule_ids:
            page = self.pages[rule_id]
            rows.append(
                "<tr>"
                f'<td class="mono"><a href="#{rule_anchor(rule_id)}">{rule_id}</a></td>'
                f"<td>{self.inline(page['title'])}</td>"
                f"<td>{self.severity_badge(page['severity'])}</td>"
                f'<td class="al-right">{self.page_ref(rule_anchor(rule_id))}</td>'
                "</tr>"
            )
        coverage = ""
        if self.mode == "pilot" and len(rule_ids) < total:
            coverage = (
                f'<p class="family-coverage">This edition covers {len(rule_ids)} of '
                f"the {total} rules in this family. The rest are listed as not yet "
                "written in the coverage report.</p>"
            )
        intro = self.markdown(family["intro"])
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<section class="family" id="{target}">\n'
            f'<p class="chapter-number">Rule family</p>\n'
            f"<h1>{html.escape(family['title'])}</h1>\n"
            f'<p class="family-prefixes">ID prefixes: {self.inline(family["prefixes"])}</p>\n'
            f"{intro}\n{coverage}\n"
            '<table class="grid family-rules"><thead><tr><th>Rule</th><th>Title</th>'
            '<th>Severity</th><th class="al-right">Page</th></tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table>\n</section>"
        )

    def severity_badge(self, severity: str) -> str:
        label = html.escape(SEVERITY_LABELS.get(severity, severity))
        css_class = html.escape(severity.lower())
        return f'<span class="sev sev-{css_class}">{label}</span>'

    def render_rule(self, page: dict) -> str:
        rule_id = page["id"]
        target = self.anchor(rule_anchor(rule_id))
        family_title = ""
        for family in self.families:
            if family["id"] == page["family"]:
                family_title = family["title"]
        entry = page["catalog"]
        targets = {item["kind"]: item for item in verification_targets(page)}
        meta = [
            ("Languages", html.escape(", ".join(page["languages"]))),
            ("Turned on by", self.run_with(page)),
            ("Finding type", html.escape(entry["finding_type"])),
            ("Gate", self.gate_text(page["gate"])),
        ]
        if page["gate"].get("opt_in"):
            meta.append(("Needs", self.inline(page["gate"]["opt_in"])))
        if page["cwe"]:
            meta.insert(1, ("CWE", html.escape(", ".join(page["cwe"]))))
        if entry["name"].strip().lower() != str(page["title"]).strip().lower():
            meta.append(("Catalog name", html.escape(entry["name"])))
        if self.aliases_by_target.get(rule_id):
            meta.append(
                (
                    "Go engine ID",
                    html.escape(", ".join(self.aliases_by_target[rule_id]))
                    + f", reported as {rule_id}",
                )
            )
        meta_html = "".join(
            f'<div class="meta-item"><span class="meta-key">{key}</span>'
            f'<span class="meta-value">{value}</span></div>'
            for key, value in meta
        )
        severity_note = ""
        if page.get("severity_note"):
            severity_note = (
                f'<p class="severity-note">{self.inline(page["severity_note"])}</p>'
            )
        steps = "".join(
            f"<li>{self.inline(step)}</li>" for step in page["how_skylos_decides"]
        )
        related = ", ".join(self.related_link(other) for other in page["related"])
        refs = "".join(
            "<li><code>"
            + html.escape(str(ref["path"]))
            + "</code> · <code>"
            + html.escape(str(ref["symbol"]))
            + "</code>"
            + self.ref_note(ref)
            + "</li>"
            for ref in page["source_refs"]
        )
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<article class="rule" id="{target}">\n'
            '<header class="rule-head">\n'
            f'<p class="rule-family">{html.escape(family_title)}</p>\n'
            f'<h2><span class="rule-id">{rule_id}</span>'
            f'<span class="rule-title">{self.inline(page["title"])}</span></h2>\n'
            f'<div class="rule-badges">{self.severity_badge(page["severity"])}</div>\n'
            f'<div class="rule-meta">{meta_html}</div>\n{severity_note}\n'
            "</header>\n"
            + self.section("What it is", f"<p>{self.inline(page['what_it_is'])}</p>")
            + self.section(
                "Why it matters", f"<p>{self.inline(page['why_it_matters'])}</p>"
            )
            + self.render_example(rule_id, targets["flagged"])
            + self.render_example(
                rule_id, targets["not_flagged"], page["flagged_example"]
            )
            + self.render_more_examples(rule_id, page, targets)
            + self.section("How Skylos decides", f'<ol class="steps">{steps}</ol>')
            + self.render_fix(rule_id, page)
            + self.render_false_alarms(rule_id, page, targets)
            + '<footer class="rule-foot">\n'
            + f'<p><span class="foot-key">Related</span> {related}</p>\n'
            + f'<div class="refs"><span class="foot-key">Source, for maintainers</span><ul>{refs}</ul></div>\n'
            + "</footer>\n</article>"
        )

    def gate_text(self, gate: dict) -> str:
        full = gate["full"]
        diff = gate.get("diff", full)
        if diff == full:
            text = f"{GATE_STATES[full]} (full and diff scans)"
        else:
            text = f"full scan: {GATE_STATES[full]}; diff scan: {GATE_STATES[diff]}"
        if gate.get("note"):
            return html.escape(text) + ". " + self.inline(gate["note"])
        return html.escape(text)

    def render_more_examples(self, rule_id: str, page: dict, targets: dict) -> str:
        pairs = page.get("more_examples") or []
        if not pairs:
            return ""
        blocks = []
        for index, pair in enumerate(pairs):
            label = language_name(pair["flagged"].get("language"))
            blocks.append(
                self.render_example(
                    rule_id, targets[f"more{index}-flagged"], None, label
                )
            )
            blocks.append(
                self.render_example(
                    rule_id,
                    targets[f"more{index}-not_flagged"],
                    pair["flagged"],
                    language_name(pair["not_flagged"].get("language")),
                )
            )
        return self.section("More languages", "".join(blocks))

    def ref_note(self, ref: dict) -> str:
        if not ref.get("note"):
            return ""
        return " — " + self.inline(ref["note"])

    def related_link(self, rule_id: str) -> str:
        name = html.escape(self.catalog[rule_id]["name"])
        label = html.escape(rule_id)
        if rule_id in self.pages:
            anchor = html.escape(rule_anchor(rule_id))
            return f'<a class="rule-link" href="#{anchor}">{label}</a> {name}'
        return f'<span class="mono">{label}</span> {name}'

    def run_with(self, page: dict) -> str:
        if page.get("run_with"):
            return self.inline(page["run_with"])
        flags = rule_scan_flags(page["id"])
        if not flags:
            return "<code>skylos .</code> (the default scan)"
        return f"<code>skylos . {html.escape(' '.join(flags))}</code> or <code>skylos . -a</code>"

    def section(self, title: str, content: str, css_class: str = "") -> str:
        extra = ""
        if css_class:
            extra = " " + css_class
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<section class="sec{extra}"><div class="sec-title">{title}</div>\n'
            f"{content}\n</section>\n"
        )

    def check_note(self, rule_id: str, item: dict | None) -> str:
        if item is None:
            return ""
        if item["manual"]:
            reason = self.inline(item["manual"])
            return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
                '<div class="verified manual">Example not machine-checked: '
                f"{reason}</div>"
            )
        checks = self.verify_report.get("checks") or {}
        flags = example_scan_flags(rule_id, item["example"])
        if item["baseline"]:
            flags = [*flags, "--baseline"]
        digest = example_digest(rule_id, item["kind"], item["example"], flags)
        check = checks.get(digest)
        if not check:
            return ""
        version = html.escape(str(self.verify_report.get("version") or ""))
        command = html.escape(" ".join(["skylos", ".", *flags]))
        lead = f"Skylos {version}, <code>{command}</code>"
        if item["kind"].startswith("suppress"):
            result = "the finding is hidden"
            if item["should_flag"]:
                result = "the finding stays"
            return f'<div class="verified">Checked. {lead}: {result}.</div>'
        if check["expected"] != "reported":
            return f'<div class="verified">Checked. {lead}: not reported.</div>'
        places = ", ".join(
            f"{html.escape(hit['file'])} line {hit['line']}"
            for hit in check.get("hits") or []
            if hit["file"] not in ("", ".")
        )
        if not places:
            return f'<div class="verified">Checked. {lead}: reported for the project.</div>'
        return f'<div class="verified">Checked. {lead}: reported at {places}.</div>'

    def reference_files(self, reference: dict | None) -> dict[str, str]:
        if not reference or reference.get("setup", "none") == "git_diff":
            return {}
        return {entry["filename"]: entry["code"] for entry in example_files(reference)}

    def render_example(
        self, rule_id: str, item: dict, reference: dict | None = None, label: str = ""
    ) -> str:
        example = item["example"]
        kind = "flagged"
        title = "Flagged"
        tag_class = "tag-flagged"
        if not item["should_flag"]:
            kind = "not_flagged"
            title = "Not flagged"
            tag_class = "tag-clean"
        if label:
            title = f"{title} · {html.escape(label)}"
        blocks = []
        setup = example.get("setup", "none")
        files = example_files(example)
        if setup == "git_diff":
            base = {entry["filename"]: entry["code"] for entry in example["base_files"]}
            changed = {entry["filename"] for entry in files}
            for entry in files:
                blocks.append(("diff", entry, base.get(entry["filename"])))
            for name, code in base.items():
                if name not in changed:
                    entry = {
                        "filename": name,
                        "code": code,
                        "language": example.get("language"),
                    }
                    blocks.append(("file", entry, ()))
        else:
            expected_file = example.get("expect_file") or files[0]["filename"]
            same = self.reference_files(reference)
            for entry in files:
                if len(files) > 1 and same.get(entry["filename"]) == entry["code"]:
                    blocks.append(("same", entry, ()))
                    continue
                lines = ()
                if (
                    kind == "flagged"
                    and example.get("expect_line")
                    and entry["filename"] == expected_file
                ):
                    lines = (example["expect_line"],)
                blocks.append(("file", entry, lines))
        note = self.check_note(rule_id, item)
        if example.get("why"):
            note = (
                '<div class="why"><strong>Why it is not flagged:</strong> '
                f"{self.inline(example['why'])}</div>{note}"
            )
        rendered = []
        for position, (shape, entry, extra) in enumerate(blocks):
            footer = ""
            if position == len(blocks) - 1:
                footer = note
            if shape == "diff":
                rendered.append(self.diff_block(entry, extra, footer))
            elif shape == "same":
                rendered.append(
                    self.figure(
                        entry["filename"],
                        "same as in the flagged example",
                        language_name(entry.get("language")),
                        "",
                        footer,
                    )
                )
            else:
                status = ""
                if setup == "git_diff":
                    status = "unchanged"
                rendered.append(self.file_block(entry, status, extra, footer))
        setup_note = ""
        if setup == "git_diff":
            setup_note = (
                '<p class="setup-note">Shown as a change against the last commit: '
                "lines starting with <code>-</code> were removed, lines starting "
                "with <code>+</code> were added.</p>"
            )
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<section class="sec example {kind}">'
            f'<div class="sec-title"><span class="tag {tag_class}">{title}</span></div>\n'
            f"{setup_note}{''.join(rendered)}\n</section>\n"
        )

    def figure(
        self, name: str, status: str, language_label: str, code_html: str, footer: str
    ) -> str:
        status_html = ""
        if status:
            status_html = f'<span class="file-status">{html.escape(status)}</span>'
        lang = ""
        if language_label:
            lang = f'<span class="file-lang">{html.escape(language_label)}</span>'
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            '<figure class="file"><figcaption>'
            f'<span class="file-name">{html.escape(name)}</span>{status_html}{lang}'
            f"</figcaption>{code_html}{footer}</figure>"
        )

    def file_block(
        self, entry: dict, status: str, highlight_lines, footer: str = ""
    ) -> str:
        language = DATA_FILE_LANGUAGES.get(
            Path(entry["filename"]).suffix.lower(), entry.get("language")
        )
        if not entry["code"].strip():
            if not status:
                status = "empty file"
            return self.figure(
                entry["filename"], status, language_name(language), "", footer
            )
        code_html = self.code_block(
            entry["code"], language, entry["filename"], highlight_lines
        )
        return self.figure(
            entry["filename"], status, language_name(language), code_html, footer
        )

    def diff_text(
        self, name: str, before: str | None, after: str | None, context: int
    ) -> str:
        old_name = f"a/{name}"
        new_name = f"b/{name}"
        if before is None:
            old_name = "/dev/null"
        if after is None:
            new_name = "/dev/null"
        lines = difflib.unified_diff(
            (before or "").splitlines(),
            (after or "").splitlines(),
            old_name,
            new_name,
            n=context,
            lineterm="",
        )
        body = []
        hunks = 0
        for line in lines:
            if line.startswith(("---", "+++")):
                continue
            if line.startswith("@@"):
                hunks += 1
                if hunks > 1:
                    body.append("…")
                continue
            body.append(line)
        return "\n".join(body) + "\n"

    def diff_block(self, entry: dict, before: str | None, footer: str = "") -> str:
        name = entry["filename"]
        status = "changed"
        after = entry["code"]
        if entry.get("deleted"):
            status = "deleted"
            after = None
        elif before is None:
            status = "new file"
        text = self.diff_text(name, before, after, 10000)
        return self.figure(name, status, "Diff", self.plain_code(text, "diff"), footer)

    def render_fix(self, rule_id: str, page: dict) -> str:
        fix = page["fix"]
        content = f"<p>{self.inline(fix['explanation'])}</p>"
        if not fix.get("code"):
            return self.section("Fix", content)
        content = f'<p class="keep-next">{self.inline(fix["explanation"])}</p>'
        language = fix.get("language") or page["flagged_example"].get("language")
        if not fix.get("filename"):
            return self.section("Fix", content + self.plain_code(fix["code"], language))
        targets = {item["kind"]: item for item in verification_targets(page)}
        note = self.check_note(rule_id, targets.get("fix"))
        flagged = page["flagged_example"]
        before = None
        if flagged.get("setup", "none") != "git_diff":
            for entry in example_files(flagged):
                if entry["filename"] == fix["filename"]:
                    before = entry["code"]
        if before is None:
            content += self.file_block(
                {
                    "filename": fix["filename"],
                    "code": fix["code"],
                    "language": language,
                },
                "",
                (),
                note,
            )
        else:
            text = self.diff_text(fix["filename"], before, fix["code"], 2)
            content += self.figure(
                fix["filename"],
                "change from the flagged example",
                "Diff",
                self.plain_code(text, "diff"),
                note,
            )
        return self.section("Fix", content)

    def render_false_alarms(self, rule_id: str, page: dict, targets: dict) -> str:
        value = page["false_alarms_and_suppression"]
        misfires = "".join(
            f"<li>{self.inline(item)}</li>" for item in value["misfires"]
        )
        suppress = []
        for index, item in enumerate(value["suppress"]):
            block = f"<li>{self.inline(item['text'])}"
            if item.get("code"):
                block += self.plain_code(item["code"], item.get("language"))
            block += self.check_note(rule_id, targets.get(f"suppress{index}"))
            block += "</li>"
            suppress.append(block)
        content = (
            '<div class="sub-title">When it can misfire</div>'
            f'<ul class="misfires">{misfires}</ul>'
            '<div class="sub-title">How to silence it</div>'
            f'<ul class="suppress">{"".join(suppress)}</ul>'
        )
        return self.section("False alarms and suppression", content)

    def reference(self) -> dict:
        if self.reference_data is None:
            self.reference_data = command_reference()
        return self.reference_data

    def command_overview_markdown(self) -> str:
        reference = self.reference()
        lines = []
        for group in reference["groups"]:
            rows = []
            for command in reference["commands"]:
                for entry in command["entries"]:
                    if entry["group"] == group:
                        rows.append(entry)
            if not rows:
                continue
            lines += ["", f"### {group}", "", "| Command | What it does |", "|:--|:--|"]
            for entry in rows:
                name = entry["name"].replace("|", "\\|")
                desc = entry["desc"].replace("|", "\\|")
                lines.append(f"| `{name}` | {desc} |")
        return "\n".join(lines)

    def render_command_appendix(self) -> str:
        target = self.anchor("commands")
        reference = self.reference()
        blocks = []
        for command in reference["commands"]:
            blocks.append(self.render_command(command))
        intro = (
            "<p>Generated when this book was built, from the argument parsers and "
            f"the help table of Skylos {html.escape(reference['version'])}. "
            "<code>skylos &lt;command&gt; --help</code> shows the same options "
            "for the version you have installed.</p>"
        )
        return (  # skylos: ignore[SKY-D228] joins HTML fragments this module escaped
            f'<section class="appendix commands" id="{target}">\n'
            '<p class="chapter-number">Appendix</p>\n'
            "<h1>Command and flag reference</h1>\n"
            f"{intro}{''.join(blocks)}\n</section>"
        )

    def render_command(self, command: dict) -> str:
        title = "skylos PATH"
        if command["key"]:
            title = f"skylos {command['key']}"
        parts = [f'<h2 class="command-title"><code>{html.escape(title)}</code></h2>']
        for entry in command["entries"]:
            details = "".join(
                f"<li>{html.escape(detail)}</li>" for detail in entry["details"]
            )
            if details:
                details = f'<ul class="command-details">{details}</ul>'
            parts.append(
                f'<p class="command-entry"><code>{html.escape(entry["name"])}</code> '
                f"— {html.escape(entry['desc'])}</p>{details}"
            )
        parser = command["parser"]
        if parser:
            parts.append(self.render_parser(parser))
        elif not command["entries"]:
            parts.append(
                "<p>No description or option list could be read for this command; "
                "run it with <code>--help</code>.</p>"
            )
        return '<div class="command">' + "".join(parts) + "</div>"

    def render_parser(self, parser: dict, level: int = 0) -> str:
        parts = []
        if parser["description"] and level:
            parts.append(f"<p>{html.escape(parser['description'])}</p>")
        parts.append(f'<pre class="usage">{html.escape(parser["usage"])}</pre>')
        if parser["options"]:
            rows = "".join(
                "<tr>"
                f'<td class="opt"><code>{html.escape(option["invocation"])}</code></td>'
                f"<td>{html.escape(option['help'])}</td>"
                "</tr>"
                for option in parser["options"]
            )
            parts.append(
                '<table class="grid options"><thead><tr><th>Option</th>'
                f"<th>What it does</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        for sub in parser["subcommands"]:
            heading = html.escape(f"{sub['name']}")
            help_text = ""
            if sub["help"]:
                help_text = f" — {html.escape(sub['help'])}"
            parts.append(
                f'<h3 class="subcommand"><code>{heading}</code>{help_text}</h3>'
                + self.render_parser(sub, level + 1)
            )
        return "".join(parts)

    def render_index(self) -> str:
        target = self.anchor("index")
        rows = []
        for rule_id in sorted(self.pages):
            page = self.pages[rule_id]
            family_title = ""
            for family in self.families:
                if family["id"] == page["family"]:
                    family_title = family["title"]
            rows.append(
                "<tr>"
                f'<td class="mono"><a href="#{rule_anchor(rule_id)}">{rule_id}</a></td>'
                f"<td>{self.inline(page['title'])}</td>"
                f"<td>{html.escape(family_title)}</td>"
                f"<td>{self.severity_badge(page['severity'])}</td>"
                f'<td class="al-right">{self.page_ref(rule_anchor(rule_id))}</td>'
                "</tr>"
            )
        note = ""
        missing = self.page_rule_count - len(self.pages)
        if self.mode == "pilot" and missing:
            note = (
                f'<p class="family-coverage">Skylos has {self.page_rule_count} rules. '
                f"This edition has pages for {len(self.pages)}; the other {missing} "
                "are listed as not yet written in the coverage report that is built with "
                "this PDF.</p>"
            )
        return (
            f'<section class="index" id="{target}">\n'
            '<p class="chapter-number">Appendix</p>\n<h1>Rule index</h1>\n'
            f"{note}"
            '<table class="grid index-table"><thead><tr><th>Rule</th><th>Title</th>'
            '<th>Family</th><th>Severity</th><th class="al-right">Page</th></tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table>\n</section>"
        )


EXTRA_PARSER_COMMANDS = frozenset({"cicd"})


class _ParserCaptured(Exception):
    pass


def capture_command_parser(call) -> argparse.ArgumentParser | None:
    """The first parser a command builds, taken when it starts parsing.

    Commands build their parser inside their run function. Parsing is
    stopped at once, so nothing the command does after parsing runs.
    """
    captured = []
    original = argparse.ArgumentParser.parse_known_args

    def stop(self, args=None, namespace=None):
        captured.append(self)
        raise _ParserCaptured

    argparse.ArgumentParser.parse_known_args = stop
    try:
        call()
    except (_ParserCaptured, SystemExit):
        pass
    finally:
        argparse.ArgumentParser.parse_known_args = original
    if captured:
        return captured[0]
    return None


def describe_parser(parser: argparse.ArgumentParser, depth: int = 0) -> dict:
    formatter = parser._get_formatter()
    options = []
    subcommands = []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction) or action.help == argparse.SUPPRESS:
            continue
        if isinstance(action, argparse._SubParsersAction):
            subcommands += describe_subparsers(action, depth)
            continue
        help_text = str(action.help or "")
        try:
            help_text = formatter._expand_help(action)
        except (KeyError, TypeError, ValueError):
            pass
        options.append(
            {
                "invocation": formatter._format_action_invocation(action),
                "help": " ".join(help_text.split()),
                "positional": not action.option_strings,
            }
        )
    return {
        "usage": " ".join(parser.format_usage().split()),
        "description": " ".join(str(parser.description or "").split()),
        "options": options,
        "subcommands": subcommands,
    }


def describe_subparsers(action, depth: int) -> list[dict]:
    helps = {choice.dest: str(choice.help or "") for choice in action._choices_actions}
    seen = set()
    result = []
    for name, sub in action.choices.items():
        if id(sub) in seen or depth >= 2:
            continue
        seen.add(id(sub))
        entry = {"name": name, "help": " ".join(helps.get(name, "").split())}
        entry.update(describe_parser(sub, depth + 1))
        result.append(entry)
    return result


def command_key(name: str) -> str:
    """`skylos setup [path]` -> `setup`; the scan entry `skylos PATH` -> ``."""
    words = name.split()
    if len(words) < 2 or words[1].isupper():
        return ""
    return words[1]


def native_command_parser(cli, handler_name: str, key: str):
    handler = getattr(cli, handler_name)
    help_argv = ["--help"]
    if key == "image":
        help_argv = ["scan", "--help"]
    return capture_command_parser(lambda: handler(help_argv))


def collect_command_reference() -> dict:
    """Every top-level command: its help-table entry and, where the command
    builds an argparse parser, every option it accepts."""
    import skylos
    from skylos import cli
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS, NATIVE_HELP_COMMANDS
    from skylos.cli_core.main_parser import build_main_parser
    from skylos.ui.help import COMMANDS

    entries_by_key: dict[str, list[dict]] = {}
    groups: list[str] = []
    for item in COMMANDS:
        key = command_key(str(item.get("name", "")))
        entries_by_key.setdefault(key, []).append(item)
        if item.get("group") and item["group"] not in groups:
            groups.append(item["group"])
    keys = [""] + sorted(
        name
        for name, handler in EARLY_COMMAND_HANDLERS.items()
        if "removed" not in handler
    )
    keys.append("agent")
    commands = []
    for key in sorted(set(keys), key=lambda name: (name != "", name)):
        parser = None
        if key == "":
            parser = build_main_parser(version=str(skylos.__version__))
        elif key == "agent":
            parser = cli._build_agent_parser()
        elif key in NATIVE_HELP_COMMANDS or key in EXTRA_PARSER_COMMANDS:
            parser = native_command_parser(cli, EARLY_COMMAND_HANDLERS[key], key)
        described = None
        if parser is not None:
            described = describe_parser(parser)
        commands.append(
            {
                "key": key,
                "entries": [
                    {
                        "name": str(item.get("name", "")),
                        "desc": str(item.get("desc", "")),
                        "group": str(item.get("group") or ""),
                        "details": [str(detail) for detail in item.get("details", [])],
                    }
                    for item in entries_by_key.get(key, [])
                ],
                "parser": described,
            }
        )
    return {"version": str(skylos.__version__), "groups": groups, "commands": commands}


def command_reference() -> dict:
    """Run collect_command_reference in a child process with a throwaway
    HOME and working folder, so building a parser cannot touch real files."""
    with tempfile.TemporaryDirectory(prefix="skylos-handbook-commands-") as folder:
        home = Path(folder) / "home"
        home.mkdir()
        env = verification_env(home)
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--dump-command-reference"],
            cwd=folder,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    if result.returncode != 0:
        raise BuildError(
            "could not read the command parsers: " + result.stderr.strip()[-800:]
        )
    return json.loads(result.stdout)


def git_short_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


if __name__ == "__main__":
    sys.exit(main())
