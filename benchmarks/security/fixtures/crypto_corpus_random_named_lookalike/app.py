import secrets

class TokenSource:
    def random(self):
        return secrets.token_urlsafe(32)

def issue(response):
    rng = TokenSource()
    response.set_cookie("sid", rng.random())
