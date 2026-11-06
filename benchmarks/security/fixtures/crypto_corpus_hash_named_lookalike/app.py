import hashlib

class DigestFactory:
    @staticmethod
    def md5(data):
        return hashlib.sha256(data).hexdigest()

def password_digest(password):
    return DigestFactory.md5(password.encode())
