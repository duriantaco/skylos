from repository import list_recent_users, search_users


def handle_search(term, limit=20, sort="created_at"):
    return search_users(term, limit=limit, sort=sort)


def handle_homepage():
    return list_recent_users(10)
