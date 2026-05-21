import requests

from services.formatters import normalize_host


def fetch_partner(target):
    host = normalize_host(target)
    return requests.get(f"https://{host}/api/status", timeout=3).json()


def fetch_internal_status():
    return requests.get("https://status.example.com/api", timeout=3).json()


def lab_fetch(url):
    return requests.get(url, timeout=3).text
