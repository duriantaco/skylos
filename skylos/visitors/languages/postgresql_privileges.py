"""Review explicit role attributes and grants in standalone PostgreSQL DDL."""

from pglast import ast, enums


def _public_grant(grant, report):
    if not grant.is_grant or grant.grant_option:
        # PostgreSQL rejects grant options for PUBLIC.
        return
    public = next(
        (
            role
            for role in grant.grantees
            if role.roletype == enums.RoleSpecType.ROLESPEC_PUBLIC
        ),
        None,
    )
    if public is None:
        return
    privileges = {priv.priv_name for priv in grant.privileges or ()}
    all_privileges = not privileges or None in privileges
    defaults = grant.targtype == enums.GrantTargetType.ACL_TARGET_DEFAULTS
    if grant.objtype == enums.ObjectType.OBJECT_SCHEMA and (
        all_privileges or "create" in privileges
    ):
        scope = (
            "new schemas covered by these defaults" if defaults else "the named schemas"
        )
        report(
            public.location,
            "SKY-D418",
            "MEDIUM",
            f"This grant gives PUBLIC permission to create objects in {scope}. "
            "Check whether every database role needs that permission.",
        )
    elif grant.objtype == enums.ObjectType.OBJECT_TABLE and (
        all_privileges
        or privileges.intersection({"insert", "update", "delete", "truncate"})
    ):
        scope = (
            "future tables covered by these defaults"
            if defaults
            else "the specified tables or columns"
        )
        report(
            public.location,
            "SKY-D420",
            "MEDIUM",
            f"This grant gives PUBLIC data modification privileges on {scope}. "
            "Check the intended writers and any applicable row-level policies.",
        )


def check_privileges(stmt, report):
    if isinstance(stmt, ast.GrantStmt):
        _public_grant(stmt, report)
    elif isinstance(stmt, ast.AlterDefaultPrivilegesStmt):
        _public_grant(stmt.action, report)
    elif isinstance(stmt, ast.CreateSchemaStmt):
        for element in stmt.schemaElts or ():
            if isinstance(element, ast.GrantStmt):
                _public_grant(element, report)
    elif isinstance(stmt, (ast.CreateRoleStmt, ast.AlterRoleStmt)):
        # CREATE USER defaults to LOGIN. ALTER preserves unknown existing attributes.
        login = (
            isinstance(stmt, ast.CreateRoleStmt)
            and stmt.stmt_type == enums.RoleStmtType.ROLESTMT_USER
        )
        bypass = None
        seen = set()
        for option in stmt.options or ():
            if option.defname in {"bypassrls", "canlogin"}:
                if option.defname in seen:
                    return  # PostgreSQL rejects redundant or conflicting options.
                seen.add(option.defname)
                if option.defname == "canlogin":
                    login = option.arg.boolval
                else:
                    bypass = option
        if login and bypass is not None and bypass.arg.boolval:
            report(
                bypass.location,
                "SKY-D419",
                "MEDIUM",
                "This statement configures a login role with BYPASSRLS. "
                "Check whether this account should bypass row-level security policies.",
            )
