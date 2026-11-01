"""SKY-D283: an unauthenticated route that controls, destroys, administers or
runs commands. The route evidence is shared with SKY-F102 and SKY-D231."""

from __future__ import annotations

import ast
import sys

_CWE = [
    {"id": "CWE-306", "name": "Missing Authentication for Critical Function"},
    {"id": "CWE-862", "name": "Missing Authorization"},
]


_KIND_PHRASES = {
    "admin": "an admin",
    "command": "a command",
    "control": "a control",
    "destructive": "a destructive",
}


def _message(entry) -> str:
    function = entry["function"]
    target = f"'{function.name}'"
    if entry["paths"]:
        target = f"'{function.name}' ({','.join(entry['methods'])} {entry['paths'][0]})"
    kinds = " and ".join(_KIND_PHRASES[kind] for kind in sorted(entry["actions"]))
    matched = sorted({word for found in entry["actions"].values() for word in found})
    message = (
        f"Route {target} performs {kinds} action "
        f"({', '.join(matched)}) and nothing on the route, in its handler or in "
        "this module authenticates the caller: anyone who can reach the server "
        "can trigger it."
    )
    if entry["binds_all_interfaces"]:
        message += " The module serves the app on every network interface."
    if not entry["auth_seen_in_module"]:
        message += " The module shows no authentication anywhere."
    return message


def scan(tree, file_path, findings):
    if not isinstance(tree, ast.Module):
        return
    try:
        from skylos.rules.quality.practices import open_unguarded_routes

        for entry in open_unguarded_routes(tree, str(file_path)):
            if entry["severity"] is None:
                continue
            function = entry["function"]
            findings.append(
                {
                    "rule_id": "SKY-D283",
                    "severity": entry["severity"],
                    "message": _message(entry),
                    "file": str(file_path),
                    "line": function.lineno,
                    "col": function.col_offset,
                    "name": function.name,
                    "simple_name": function.name,
                    "cwe": list(_CWE),
                    "route_exposure": {
                        "version": 1,
                        "methods": entry["methods"],
                        "paths": entry["paths"],
                        "actions": entry["actions"],
                        "binds_all_interfaces": entry["binds_all_interfaces"],
                        "auth_seen_in_module": entry["auth_seen_in_module"],
                    },
                }
            )
    except Exception as error:
        print(f"Route auth analysis failed for {file_path}: {error}", file=sys.stderr)
