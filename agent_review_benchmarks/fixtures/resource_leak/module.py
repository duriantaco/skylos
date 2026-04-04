def load_first_line(path):
    handle = open(path, encoding="utf-8")
    if path.endswith(".json"):
        return handle.readline().strip()
    return handle.read().splitlines()[0]


def safe_preview(path):
    with open(path, encoding="utf-8") as handle:
        return handle.readline().strip()
