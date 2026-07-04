async def refresh_cache(client):
    try:
        return await client.fetch_latest()
    except Exception:
        return None
