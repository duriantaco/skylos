import random
import secrets

def issue(response, fallback):
    value = secrets.token_urlsafe(32)
    if fallback:
        value = str(random.getrandbits(128))
    response.set_cookie("sid", value)
