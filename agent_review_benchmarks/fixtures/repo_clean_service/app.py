from formatter import normalize_headers
from service import fetch_status


def handle_status(headers):
    safe_headers = normalize_headers(headers)
    return {"status": fetch_status(), "headers": safe_headers}
