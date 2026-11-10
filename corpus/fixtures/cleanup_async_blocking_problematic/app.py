import requests


async def fetch_quote(endpoint: str) -> dict[str, object]:
    response = requests.get(endpoint, timeout=3)
    response.raise_for_status()
    return response.json()
