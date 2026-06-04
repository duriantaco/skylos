def format_preview(title, body):
    clean_title = title.strip()
    clean_body = body.strip()
    return {
        "title": clean_title,
        "body": clean_body[:120],
    }


def submit_generated_payload(payload):
    cleaned = normalize_payload(payload)
    return {
        "payload": cleaned,
        "queued": True,
    }
