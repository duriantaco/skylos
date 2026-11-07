import secrets as rng
import random

rng = random.Random()

def issue(response):
    response.set_cookie("sid", str(rng.getrandbits(128)))
