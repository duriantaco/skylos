import requests
import time


async def fetch_profile(user_id):
    time.sleep(0.1)
    response = requests.get(
        f"https://api.example.test/users/{user_id}",
        timeout=5,
    )
    return response.json()


async def fetch_health():
    return {"status": "ok"}
