"""Compare explicit PUBLIC table write grants within a parsed migration."""

import re
from bisect import bisect_right
from copy import copy
from dataclasses import dataclass, replace
from hashlib import sha256

from pglast import ast, enums
from pglast.parser import ParseError
from pglast.stream import RawStream
from pglast.visitors import Visitor

from .postgresql_privileges import TABLE_WRITES, public_grant_finding
from .postgresql_script import parse_script


@dataclass(frozen=True)
class WriteGrant:
    fingerprint: str
    line: int
    scope: tuple
    targets: frozenset
    rights: frozenset
    occurrence: int | None = None

    def covered_by(self, prior):
        targets, rights = prior
        return self.targets <= targets and all(
            (action, col) in rights or (action, None) in rights
            for action, col in self.rights
        )


_RESOLUTION_SETTINGS = {"search_path", "role", "session_authorization"}


class _Settings(Visitor):
    mode = None

    def visit_FuncCall(self, ancestors, node):
        if node.funcname[-1].sval.lower() == "set_config":
            name = node.args[0] if node.args else None
            if (
                not (isinstance(name, ast.A_Const) and isinstance(name.val, ast.String))
                or name.val.sval.lower() in _RESOLUTION_SETTINGS
            ):
                local = node.args[2] if node.args and len(node.args) > 2 else None
                if isinstance(local, ast.A_Const) and isinstance(
                    local.val, ast.Boolean
                ):
                    mode = "local" if local.val.boolval else "session"
                else:
                    mode = "unknown"
                self.mode = mode if self.mode in (None, mode) else "unknown"


def _grant_parts(stmt):
    if isinstance(stmt, ast.GrantStmt):
        yield stmt, stmt
    elif isinstance(stmt, ast.AlterDefaultPrivilegesStmt):
        yield stmt, stmt.action
    elif isinstance(stmt, ast.CreateSchemaStmt):
        for element in stmt.schemaElts or ():
            if isinstance(element, ast.GrantStmt):
                wrapper = copy(stmt)
                wrapper.schemaElts = (element,)
                yield wrapper, element


def _identity(context, statement):
    digest = context.copy()
    digest.update(RawStream()(statement).encode("utf-8"))
    return digest.digest()


def _write_grant(statement, grant, line, context):
    exact = _identity(context, statement).hex()
    rights = set()
    for priv in grant.privileges or (ast.AccessPriv(),):
        actions = {priv.priv_name} & TABLE_WRITES if priv.priv_name else TABLE_WRITES
        rights.update(
            (action, col.sval if col else None)
            for action in actions
            for col in priv.cols or (None,)
        )

    # Compare only PUBLIC writes for baseline credit. The exception still
    # identifies the entire statement, including privileges and other roles.
    container = None
    if isinstance(statement, ast.CreateSchemaStmt):
        schema = copy(statement)
        schema.schemaElts = None
        container = RawStream()(schema)
    elif isinstance(statement, ast.AlterDefaultPrivilegesStmt):
        defaults = copy(statement)
        defaults.action = copy(grant)
        defaults.action.is_grant = True
        defaults.action.behavior = enums.DropBehavior.DROP_RESTRICT
        defaults.action.privileges = None
        defaults.action.grantees = tuple(
            role
            for role in grant.grantees
            if role.roletype == enums.RoleSpecType.ROLESPEC_PUBLIC
        )
        container = RawStream()(defaults)
    scope = (
        context.digest(),
        container,
        grant.targtype,
        RawStream()(grant.grantor) if grant.grantor else None,
    )
    targets = frozenset(RawStream()(obj) for obj in grant.objects or ())
    return WriteGrant(exact, line, scope, targets, frozenset(rights))


def _connection_context(source, start):
    # Each new session begins after a validated psql connection.
    connection = source[source.rfind("\n", 0, max(0, start - 1)) + 1 : start].strip()
    return sha256(connection.encode("utf-8"))


def _resolution_change(stmt):
    settings = _Settings()
    settings(stmt)
    mode = settings.mode
    if isinstance(stmt, ast.VariableSetStmt) and (
        stmt.name is None or stmt.name.lower() in _RESOLUTION_SETTINGS
    ):
        mode = "local" if stmt.is_local else "session"
    elif isinstance(stmt, (ast.DiscardStmt, ast.RenameStmt, ast.AlterObjectSchemaStmt)):
        mode = "session"
    elif isinstance(stmt, (ast.CallStmt, ast.DoStmt, ast.ExecuteStmt)):
        mode = "unknown"
    if mode:
        return RawStream()(stmt).encode("utf-8") + b"\0", mode
    return None


def statements_with_context(source, sessions):
    """Yield every advisory statement with its explicit resolution context."""
    for start, statements in sessions:
        context = _connection_context(source, start)
        seen_change = False
        for raw in statements:
            stmt = raw.stmt
            yield start, context, stmt
            change = _resolution_change(stmt)
            if change:
                context.update(change[0])
                seen_change = True
            elif seen_change and isinstance(stmt, ast.TransactionStmt):
                context.update(RawStream()(stmt).encode("utf-8") + b"\0")


def _committed_batches(statements):
    """Project only explicit transaction outcomes. Never infer a prepared transaction."""
    kind = enums.TransactionStmtKind
    pending = None
    savepoints = []
    for raw in statements:
        stmt = raw.stmt
        if not isinstance(stmt, ast.TransactionStmt):
            if pending is None:
                yield (raw,)
            else:
                pending.append(raw)
            continue
        if stmt.kind in (kind.TRANS_STMT_BEGIN, kind.TRANS_STMT_START):
            if pending is None:
                pending = []
        elif stmt.kind in (kind.TRANS_STMT_COMMIT, kind.TRANS_STMT_ROLLBACK):
            if pending is None and stmt.kind == kind.TRANS_STMT_ROLLBACK:
                raise ValueError(
                    "Cannot resolve ROLLBACK outside an explicit transaction."
                )
            if pending is not None and stmt.kind == kind.TRANS_STMT_COMMIT:
                yield pending
            pending = [] if stmt.chain else None
            savepoints.clear()
        elif stmt.kind == kind.TRANS_STMT_SAVEPOINT and pending is not None:
            savepoints.append((stmt.savepoint_name, len(pending)))
        elif (
            stmt.kind in (kind.TRANS_STMT_ROLLBACK_TO, kind.TRANS_STMT_RELEASE)
            and pending is not None
        ):
            for i in range(len(savepoints) - 1, -1, -1):
                name, position = savepoints[i]
                if name == stmt.savepoint_name:
                    if stmt.kind == kind.TRANS_STMT_ROLLBACK_TO:
                        del pending[position:]
                        del savepoints[i + 1 :]
                    else:
                        del savepoints[i:]
                    break
            else:
                raise ValueError("Cannot resolve savepoint in protected migration.")
        else:
            raise ValueError(
                "Cannot resolve external or two-phase transaction for PUBLIC grants."
            )
    if pending:
        raise ValueError("Missing transaction outcome for protected migration.")


def _after_revoke(grants, revoke):
    """Subtract only explicit PUBLIC rights on the same targets and grantor."""
    for prior in grants:
        affected = prior.targets & revoke.targets
        if (
            prior.scope != revoke.scope
            or (prior.targets or revoke.targets)
            and not affected
        ):
            yield prior
            continue
        remaining = frozenset(
            (action, col)
            for action, col in prior.rights
            if (action, col) not in revoke.rights
            and (action, None) not in revoke.rights
        )
        if remaining == prior.rights:
            yield prior
            continue
        unaffected = prior.targets - affected
        if unaffected:
            yield replace(prior, targets=unaffected)
        if remaining:
            yield replace(prior, targets=affected, rights=remaining)


class MigrationGrants(list):
    """Rights surviving at end of file, plus each grant observable at a commit."""

    def __init__(self):
        super().__init__()
        self.exposed = []


def _write_finding(grant):
    # GRANT OPTION FOR does not revoke the underlying permission. The
    # existing D420 classifier excludes grant options to PUBLIC.
    probe = copy(grant)
    probe.is_grant = True
    finding = public_grant_finding(probe)
    return finding if finding and finding[1] == "SKY-D420" else None


def migration_grants(source, collect, *, parsed=None):
    if "\0" in source:
        raise ValueError("PostgreSQL source contains a NUL character.")
    try:
        source, sessions = parse_script(source) if parsed is None else parsed
    except ParseError as exc:
        raise ValueError(str(exc)) from exc
    result = MigrationGrants()
    if not collect:
        return result
    newlines = [m.end() - 1 for m in re.finditer(r"\r\n?|\n", source)]
    occurrence = 0
    for start, statements in sessions:
        if not any(
            _write_finding(grant)
            for raw in statements
            for _, grant in _grant_parts(raw.stmt)
        ):
            continue
        durable = _connection_context(source, start)
        for batch in _committed_batches(statements):
            active = durable.copy()
            incoming = []
            for raw in batch:
                stmt = raw.stmt
                for wrapper, grant in _grant_parts(stmt):
                    finding = _write_finding(grant)
                    if not finding:
                        continue
                    line = 1 + bisect_right(newlines, start + finding[0])
                    item = _write_grant(wrapper, grant, line, active)
                    if grant.is_grant:
                        incoming.append(replace(item, occurrence=occurrence))
                        occurrence += 1
                    else:
                        result[:] = _after_revoke(result, item)
                        incoming = list(_after_revoke(incoming, item))
                change = _resolution_change(stmt)
                if change:
                    value, mode = change
                    # SET ... FROM CURRENT and expressions can depend on a
                    # preceding local setting. Preserve that context too.
                    if mode != "local" and active.digest() != durable.digest():
                        durable.update(active.digest())
                    active.update(value)
                    if mode != "local":
                        durable.update(value)
                        if mode == "unknown":
                            durable.update(b"after transaction\0")
            result.exposed.extend(incoming)
            result.extend(incoming)
    return result
