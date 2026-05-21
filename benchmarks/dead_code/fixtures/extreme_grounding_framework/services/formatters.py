ALLOWED_SORTS = {"created_at", "email", "id"}


def normalize_sort(value):
    if value in ALLOWED_SORTS:
        return value
    return "created_at"


def normalize_host(value):
    return str(value).strip().lower()
