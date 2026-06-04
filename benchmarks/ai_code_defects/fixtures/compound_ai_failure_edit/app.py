import requests


def sync_profile(request):
    token = validate_token(request.headers["Authorization"])
    profile = requests.fetch_json(
        "https://api.example.com/profile",
        params={"id": token},
    )
    return profile


def complete_later(payload):
    pass
