"""Backend factories exposed through package entry points."""


def open_amber(location):
    return {"location": location, "ready": True}


def open_birch(location):
    return {"location": location, "ready": False}


def close_cobalt(location):
    return {"location": location, "ready": None}
