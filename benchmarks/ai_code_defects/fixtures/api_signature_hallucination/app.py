import requests


def sync_remote_profile(user_id):
    response = requests.fetch_json(
        "https://api.example.com/users",
        params={"id": user_id},
    )
    return response


def stream_remote_profile(user_id):
    return requests.open_stream(
        "https://api.example.com/users",
        params={"id": user_id},
    )
