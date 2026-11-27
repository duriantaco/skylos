"""Checks for migration statements whose restrictions are visible in PostgreSQL source."""

from pglast import ast, enums


def _check_foreign_key(constraint, local_columns, report):
    if constraint.contype != enums.ConstrType.CONSTR_FOREIGN or not constraint.pk_attrs:
        # REFERENCES parent without a column list uses the parent's primary key.
        return
    target_columns = len(constraint.pk_attrs)
    if local_columns != target_columns:
        report(
            constraint.location,
            "SKY-Q508",
            "MEDIUM",
            f"Foreign key has {local_columns} referencing and {target_columns} "
            "referenced columns. Match the columns on both sides in order.",
        )


def _check_constraints(stmt, report):
    if isinstance(stmt, ast.CreateSchemaStmt):
        for declaration in stmt.schemaElts or ():
            _check_constraints(declaration, report)
        return
    if isinstance(stmt, ast.CreateStmt):
        definitions = stmt.tableElts or ()
    elif (
        isinstance(stmt, ast.AlterTableStmt)
        and stmt.objtype == enums.ObjectType.OBJECT_TABLE
    ):
        definitions = (
            cmd.def_
            for cmd in stmt.cmds
            if cmd.subtype
            in {
                enums.AlterTableType.AT_AddColumn,
                enums.AlterTableType.AT_AddConstraint,
            }
        )
    else:
        return

    for definition in definitions:
        if isinstance(definition, ast.ColumnDef):
            for constraint in definition.constraints or ():
                _check_foreign_key(constraint, 1, report)
        elif isinstance(definition, ast.Constraint):
            _check_foreign_key(definition, len(definition.fk_attrs or ()), report)


def scan_migrations(statements, report):
    """Review top-level commands from one session, keeping explicit transaction state."""
    in_transaction = False
    transaction = enums.TransactionStmtKind
    for raw in statements:
        stmt = raw.stmt
        if isinstance(stmt, ast.TransactionStmt):
            if stmt.kind in {
                transaction.TRANS_STMT_BEGIN,
                transaction.TRANS_STMT_START,
            }:
                in_transaction = True
            elif stmt.kind in {
                transaction.TRANS_STMT_COMMIT,
                transaction.TRANS_STMT_ROLLBACK,
            }:
                in_transaction = in_transaction and stmt.chain
            elif stmt.kind == transaction.TRANS_STMT_PREPARE:
                in_transaction = False
            continue

        if isinstance(stmt, ast.IndexStmt) and stmt.concurrent:
            command = "CREATE INDEX CONCURRENTLY"
        elif (
            isinstance(stmt, ast.DropStmt)
            and stmt.removeType == enums.ObjectType.OBJECT_INDEX
            and stmt.concurrent
        ):
            command = "DROP INDEX CONCURRENTLY"
            if (
                len(stmt.objects) > 1
                or stmt.behavior == enums.DropBehavior.DROP_CASCADE
            ):
                report(
                    raw.stmt_location,
                    "SKY-Q507",
                    "MEDIUM",
                    "DROP INDEX CONCURRENTLY accepts one index and rejects CASCADE. "
                    "Handle each index and its dependencies separately.",
                )
        else:
            _check_constraints(stmt, report)
            continue
        if in_transaction:
            report(
                raw.stmt_location,
                "SKY-Q506",
                "MEDIUM",
                f"PostgreSQL rejects {command} inside an explicit transaction. "
                "Run the concurrent index command outside the transaction block.",
            )
