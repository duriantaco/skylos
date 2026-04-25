async def fetch_status(client, user_id):
    response = await client.get(f"/users/{user_id}")
    if response.status == 404:
        return None
    response.raise_for_status()
    return await response.json()


def normalize_headers(headers=None):
    current = headers or {}
    return {key.lower(): value for key, value in current.items()}
