import random
import secrets

def issue(response):
    value = str(random.getrandbits(128))
    value = secrets.token_urlsafe(32)
    response.set_cookie("sid", value)
