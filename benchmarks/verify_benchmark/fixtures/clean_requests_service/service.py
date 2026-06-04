import requests


def build_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def fetch_profile(session, user_id, token):
    response = session.request(
        "GET",
        "https://api.example.com/users",
        params={"id": user_id},
        headers=build_headers(token),
        timeout=5,
    )
    return response.json()


def create_session():
    return requests.Session()
