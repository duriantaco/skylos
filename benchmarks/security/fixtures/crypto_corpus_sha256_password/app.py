import hashlib

def password_digest(password):
    return hashlib.sha256(password.encode()).hexdigest()
