import requests


def fetch_host(host):
    return requests.get(f"https://{host}/status", timeout=3)
