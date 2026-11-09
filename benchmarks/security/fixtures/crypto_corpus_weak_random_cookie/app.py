import random

def issue(response):
    value = str(random.getrandbits(128))
    response.set_cookie("sid", value)
