import requests
from requests import Request as HttpRequest


def build_user_request(user_id):
    return requests.Request(
        "GET",
        "https://api.example.com/users",
        params={"id": user_id},
        retry_policy="aggressive",
    )


def build_audit_request(user_id):
    return HttpRequest(
        "GET",
        "https://api.example.com/audit",
        params={"id": user_id},
        json_body=True,
    )
