import jwt


def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})
