import requests

STOCK_URL = "https://staging.inventory.internal/stock"


def sync_stock() -> list[dict[str, object]]:
    response = requests.get(STOCK_URL, timeout=5)
    response.raise_for_status()
    rows: list[dict[str, object]] = response.json()
    return rows
