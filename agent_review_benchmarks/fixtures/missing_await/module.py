async def fetch_user(client, user_id):
    return await client.get(f"/users/{user_id}")


async def load_dashboard(client, user_id):
    profile = fetch_user(client, user_id)
    return {"profile": profile}


async def load_dashboard_ok(client, user_id):
    profile = await fetch_user(client, user_id)
    return {"profile": profile}
