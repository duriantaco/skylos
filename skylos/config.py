from pathlib import Path

DEFAULTS = {
    "complexity": 10,
    "nesting": 3,
    "max_args": 5,
    "max_lines": 50,
    "ignore": [],
}


def load_config(start_path):
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent

    root_config = None

    while True:
        toml_path = current / "pyproject.toml"
        if toml_path.exists():
            root_config = toml_path
            break
        if current.parent == current:
            break
        current = current.parent

    if not root_config:
        return DEFAULTS.copy()

    try:
        import tomllib  # pragma: no skylos
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return DEFAULTS.copy()

    try:
        with open(root_config, "rb") as f:
            data = tomllib.load(f)

        user_cfg = data.get("tool", {}).get("skylos", {})

        gate_cfg = data.get("tool", {}).get("skylos", {}).get("gate", {})
        user_cfg["gate"] = gate_cfg

        final_cfg = DEFAULTS.copy()
        final_cfg.update(user_cfg)
        return final_cfg

    except Exception:
        return DEFAULTS.copy()
