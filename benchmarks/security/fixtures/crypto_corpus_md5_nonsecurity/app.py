import hashlib

def content_fingerprint(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
