import requests


def fetch_host(host):
    # A helper parameter is caller/operator configuration, not attacker input:
    # the call site decides whether this is SSRF.
    return requests.get(f"https://{host}/status", timeout=3)
