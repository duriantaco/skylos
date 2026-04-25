import os


BASE_DIR = "/srv/app/uploads"


def read_upload(filename):
    safe_name = os.path.basename(filename)
    path = os.path.join(BASE_DIR, safe_name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
