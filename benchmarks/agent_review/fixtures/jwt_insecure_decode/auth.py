import jwt


def decode_session(token):
    return jwt.decode(token, options={"verify_signature": False})


def decode_signed_session(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])
