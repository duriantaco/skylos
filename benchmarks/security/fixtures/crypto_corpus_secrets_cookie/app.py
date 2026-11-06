import secrets

def issue(response):
    response.set_cookie("sid", secrets.token_urlsafe(32))
