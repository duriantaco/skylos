import hashlib

def cache_key(password):
    return hashlib.md5(password.encode(), usedforsecurity=True).hexdigest()
