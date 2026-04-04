def normalize_name(value, default=None):
    if value is None:
        return default
    return value.strip().title()


def join_parts(parts):
    return "-".join(part.strip() for part in parts if part)
