"""Identify security review findings by the PostgreSQL operation that produces them."""

import re
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import replace

from pglast import ast
from pglast.parser import ParseError
from pglast.stream import RawStream

from skylos.cicd.postgres_check import _introduced, _unmatched

from .postgresql import _definer_option
from .postgresql_grant_policy import (
    _grant_parts,
    _write_grant,
    migration_grants,
    statements_with_context,
)
from .postgresql_privileges import login_bypass_option, public_grant_finding
from .postgresql_script import parse_script


def _security_reviews(source):
    if "\0" in source:
        raise ValueError("NUL in PostgreSQL source")
    try:
        framed, sessions = parse_script(source)
    except ParseError as exc:
        raise ValueError(str(exc)) from exc
    newlines = [m.end() - 1 for m in re.finditer(r"\r\n?|\n", framed)]
    grants = defaultdict(list)
    reviews = []
    for start, context, stmt in statements_with_context(framed, sessions):
        for wrapper, grant in _grant_parts(stmt):
            finding = public_grant_finding(grant)
            if finding:
                offset, rule, *_ = finding
                item = _write_grant(
                    wrapper, grant, 1 + bisect_right(newlines, start + offset), context
                )
                if rule == "SKY-D418":
                    # CREATE is the security-relevant permission in a schema grant.
                    item = replace(item, rights=frozenset({("create", None)}))
                grants[rule].append(item)
        if isinstance(stmt, (ast.CreateFunctionStmt, ast.AlterFunctionStmt)):
            option = _definer_option(stmt)
            if option is None:
                continue
            if isinstance(stmt, ast.CreateFunctionStmt):
                signature = (
                    tuple(part.sval for part in stmt.funcname),
                    tuple(
                        (p.mode, RawStream()(p.argType)) for p in stmt.parameters or ()
                    ),
                    stmt.is_procedure,
                )
            else:
                signature = (RawStream()(stmt.func), stmt.objtype)
            reviews.append(
                (
                    "SKY-D417",
                    1 + bisect_right(newlines, start + option.location),
                    (context.digest(), signature),
                )
            )
        elif isinstance(stmt, (ast.CreateRoleStmt, ast.AlterRoleStmt)):
            option = login_bypass_option(stmt)
            if option is None:
                continue
            role = stmt.role if isinstance(stmt.role, str) else RawStream()(stmt.role)
            reviews.append(
                (
                    "SKY-D419",
                    1 + bisect_right(newlines, start + option.location),
                    (context.digest(), role),
                )
            )
    effective_writes = []
    if grants.get("SKY-D420"):
        try:
            effective_writes = migration_grants(source, True, parsed=(framed, sessions))
        except (ValueError, RuntimeError):
            # Preserve statement-level evidence when transaction outcomes are unknown.
            effective_writes = None
    return grants, reviews, effective_writes


def new_review_locations(before, after, ranges):
    """Compare occurrences, prioritizing existing lines when a duplicate was added."""
    old_grants, old_routines_roles, previous = _security_reviews(before)
    grants, routines_roles, current = _security_reviews(after)

    def changed(line):
        return any(start <= line <= end for start, end in ranges)

    new = Counter()
    head_locations = set()
    for rule, rows in grants.items():
        head_locations.update((rule, row.line) for row in rows)
        if rule == "SKY-D420":
            if previous is None or current is None:
                new.update((rule, row.line) for row in rows)
            else:
                current.sort(key=lambda g: changed(g.line))
                current.exposed.sort(key=lambda g: changed(g.line))
                for item in _introduced(current, previous, "", ()):
                    new[rule, item["line"]] += 1
            continue
        rows.sort(key=lambda grant: changed(grant.line))
        for _, grant in _unmatched(rows, old_grants[rule], "", ()):
            new[rule, grant.line] += 1
    known = Counter((rule, key) for rule, _, key in old_routines_roles)
    for rule, line, key in sorted(routines_roles, key=lambda r: changed(r[1])):
        head_locations.add((rule, line))
        if known[rule, key]:
            known[rule, key] -= 1
        else:
            new[rule, line] += 1
    return head_locations, new
