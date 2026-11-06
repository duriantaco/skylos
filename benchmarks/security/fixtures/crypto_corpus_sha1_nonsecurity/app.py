import hashlib

def content_fingerprint(data):
    return hashlib.new("sha1", data, usedforsecurity=False).hexdigest()
