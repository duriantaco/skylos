def parse_payload(payload):
    try:
        return int(payload)
    except Exception:
        pass

    return 0
