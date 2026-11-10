import httpx


async def fetch_quote(endpoint: str) -> dict[str, object]:
    async with httpx.AsyncClient(timeout=3) as client:
        response = await client.get(endpoint)
        response.raise_for_status()
        return response.json()
