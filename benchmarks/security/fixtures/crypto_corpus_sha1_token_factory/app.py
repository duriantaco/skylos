from hashlib import new as make_digest

def token_digest(api_token):
    return make_digest("SHA1", api_token).hexdigest()
