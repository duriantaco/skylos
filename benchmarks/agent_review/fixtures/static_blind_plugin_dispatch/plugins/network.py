import requests


def fetch_url(payload):
    url = payload.get("url", "https://example.com")
    return requests.get(url, timeout=3).text


def fetch_fixed_status(payload):
    return requests.get("https://status.example.com/api", timeout=3).json()


def lab_fetch(payload):
    return requests.get(payload.get("url", "https://lab.example.com"), timeout=3).text
