def build_request(user_id, account_id, region, timeout, retries):
    return {
        "user_id": user_id,
        "account_id": account_id,
        "region": region,
        "timeout": timeout,
        "retries": retries,
    }


def helper(user_id, timeout=1):
    return user_id, timeout
