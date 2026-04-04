def parse_payload(payload):
    try:
        return int(payload)
    except ValueError:
        pass

    return 0
