import random as rng
import secrets

rng = secrets.SystemRandom()

def issue(response):
    response.set_cookie("sid", str(rng.getrandbits(128)))
