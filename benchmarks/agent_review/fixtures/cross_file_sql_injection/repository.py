from db import query_all


def search_users(term, limit=20, sort="created_at"):
    sql = (
        f"SELECT id, email FROM users "
        f"WHERE email LIKE '%{term}%' "
        f"ORDER BY {sort} LIMIT {limit}"
    )
    return query_all(sql)


def list_recent_users(limit=20):
    sql = "SELECT id, email FROM users ORDER BY created_at DESC LIMIT ?"
    return query_all(sql, [limit])
