import hashlib

def password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()
