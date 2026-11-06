import random

def issue(response):
    rng = random.SystemRandom()
    response.set_cookie("sid", str(rng.getrandbits(128)))
