import os


BASE_DIR = "/srv/app/uploads"


def read_upload(filename):
    path = os.path.join(BASE_DIR, filename)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
