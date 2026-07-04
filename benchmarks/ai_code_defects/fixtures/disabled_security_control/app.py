import requests


def fetch_profile():
    return requests.get("https://profiles.example/internal", verify=False, timeout=5)
