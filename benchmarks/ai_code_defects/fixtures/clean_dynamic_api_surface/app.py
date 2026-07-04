import requests


def build_dynamic_request(user_id):
    request_builder = getattr(requests, "Request")
    options = {"params": {"id": user_id}}
    return request_builder("GET", "https://api.example.com/users", **options)


def build_known_member_request(user_id):
    return requests.Request(
        "POST",
        "https://api.example.com/users",
        json={"id": user_id},
    )
