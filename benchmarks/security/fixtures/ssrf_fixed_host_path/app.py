import requests


def fetch_user(user_id):
    return requests.get(f"https://api.example.com/users/{user_id}", timeout=3)
