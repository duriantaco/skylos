def store_profile(store, profile: dict[str, str]) -> None:
    try:
        store.save(profile)
    except Exception:
        pass
