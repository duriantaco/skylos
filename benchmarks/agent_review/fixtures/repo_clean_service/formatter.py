def normalize_headers(headers):
    if not headers:
        return {}
    return {str(key).lower(): str(value).strip() for key, value in headers.items()}
