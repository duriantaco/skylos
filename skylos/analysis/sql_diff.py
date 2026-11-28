"""Select PostgreSQL security findings introduced by a Git change."""

import subprocess
from collections import defaultdict
from hashlib import sha256
from pathlib import Path

from skylos.analysis.sql_files import POSTGRES_DUMP_BYTE_LIMIT
from skylos.cicd.postgres_check import _entries
from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.reporting.finding_types import is_custom_finding
from skylos.reporting.listing import POSTGRESQL_SECURITY_REVIEWS
from skylos.security.regression_diff import changed_sources


def postgres_review_diff(
    findings, root, base_ref, ranges_by_file, *, working_tree, prefiltered
):
    """Return decisions only for recognized reviews; other findings use line overlap."""
    from skylos.cicd.review import _project_relative_file

    by_file = defaultdict(list)
    for finding in findings:
        rule = finding.get("rule_id")
        if (
            not isinstance(rule, str)
            or rule not in POSTGRESQL_SECURITY_REVIEWS
            or is_custom_finding(finding)
        ):
            continue
        expected = POSTGRESQL_SECURITY_REVIEWS[rule]
        review = finding.get("review_item")
        if not (
            finding.get("category") == "danger"
            and finding.get("_review_only_kind") == expected
            or isinstance(review, dict)
            and review.get("kind") == expected
            and review.get("blocking") is False
        ):
            continue
        path = _project_relative_file(finding.get("file"), root)
        if path and path.lower().endswith(".sql"):
            by_file[path].append(finding)
    if not by_file:
        return {}

    try:
        context = GitContext.from_path(root)
        merge = context.run("merge-base", "--", base_ref, "HEAD")
        if merge.returncode:
            return {}
        base = merge.stdout.strip()
        changes = changed_sources(context, base, head=None if working_tree else "HEAD")
    except (ValueError, OSError, subprocess.SubprocessError):
        if prefiltered:
            decisions = {}
            for rows in by_file.values():
                for row in rows:
                    row["_postgres_unverified_location"] = True
                    decisions[id(row)] = True
            return decisions
        return {}

    decisions = {}
    for path, rows in by_file.items():
        change = changes.get(path)
        untracked = working_tree and change is None and path in ranges_by_file
        if (change is None and not untracked) or (change and change.deleted):
            if prefiltered:
                for row in rows:
                    row["_postgres_unverified_location"] = True
                    decisions[id(row)] = True
            continue
        try:
            if working_tree:
                after = read_project_text_no_symlink(
                    root,
                    Path(root) / path,
                    max_bytes=POSTGRES_DUMP_BYTE_LIMIT,
                    encoding="utf-8-sig",
                    newline="",
                )
                if after is None:
                    continue
            else:
                after = _entries(root, "HEAD", [path])[path].text(
                    root, POSTGRES_DUMP_BYTE_LIMIT
                )
            digest = sha256(after.encode("utf-8")).hexdigest()
            pending = []
            for row in rows:
                receipt = row.get("_postgres_diff") or {}
                if prefiltered and receipt and receipt.get("source_sha256") != digest:
                    decisions[id(row)] = True
                    row["_postgres_unverified_location"] = True
                elif prefiltered and receipt.get("base") == base:
                    decisions[id(row)] = True
                else:
                    pending.append(row)
            if not pending:
                continue
            before = ""
            if change is not None and change.base_path is not None:
                old_entry = _entries(root, base, [change.base_path])[change.base_path]
                before = old_entry.text(root, POSTGRES_DUMP_BYTE_LIMIT)
            from skylos.visitors.languages.postgresql_review_diff import (
                new_review_locations,
            )

            locations, new = new_review_locations(
                before, after, ranges_by_file.get(path, ())
            )
        except (
            ImportError,
            KeyError,
            ValueError,
            RuntimeError,
            OSError,
            subprocess.SubprocessError,
        ):
            decisions.update((id(row), True) for row in rows)
            if not working_tree:
                for row in rows:
                    row["_postgres_unverified_location"] = True
            continue
        for row in pending:
            key = (row["rule_id"], row["line"])
            if key in locations:
                decisions[id(row)] = new[key] > 0
                if new[key]:
                    new[key] -= 1
                    if working_tree:
                        row["review_item"] = {
                            **row["review_item"],
                            "diff": {"base": base, "source_sha256": digest},
                        }
                elif prefiltered and not row.get("_postgres_diff"):
                    row["_postgres_unverified_location"] = True
                    decisions[id(row)] = True
            elif prefiltered:
                row["_postgres_unverified_location"] = True
                decisions[id(row)] = True
    return decisions
