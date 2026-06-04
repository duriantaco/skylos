import requests
from requests import Request as PreparedRequest


def build_profile_update(user_id, email):
    return PreparedRequest(
        "POST",
        "https://api.example.com/users",
        json={"id": user_id, "email": email},
        retry_policy="linear",
    )


def build_profile_delete(user_id):
    return requests.Request(
        "DELETE",
        "https://api.example.com/users",
        params={"id": user_id},
        json_body=False,
    )
