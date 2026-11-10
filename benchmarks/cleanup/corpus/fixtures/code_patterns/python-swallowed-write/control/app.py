def store_profile(store, profile: dict[str, str]) -> None:
    try:
        store.save(profile)
    except Exception as error:
        raise RuntimeError("Profile persistence failed") from error
