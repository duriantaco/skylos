def build_fallbacks(count: int) -> list[dict[str, str]]:
    return [{"status": "missing"} for _ in range(count)]
