from services.db import execute, query_all
from services.formatters import normalize_sort


def load_account(email, sort):
    safe_sort = normalize_sort(sort)
    query = (
        f"SELECT id, email FROM customers "
        f"WHERE email = '{email}' "
        f"ORDER BY {safe_sort}"
    )
    return query_all(query)


def archive_account(user_id):
    query = "SELECT id, closed_at FROM archived_customers WHERE id = ?"
    return query_all(query, [user_id])


def dormant_report(where_clause):
    query = f"SELECT id FROM diagnostics WHERE {where_clause}"
    return execute(query)
