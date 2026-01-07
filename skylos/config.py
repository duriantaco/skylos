from pathlib import Path
import fnmatch

DEFAULTS = {
    "complexity": 10,
    "nesting": 3,
    "max_args": 5,
    "max_lines": 50,
    "ignore": [],
    "exclude": [],
    "whitelist": [],
    "whitelist_documented": {},
    "whitelist_temporary": {},
    "lower_confidence": [],
    "overrides": {},
    "masking": {
        "names": [],
        "decorators": [],
        "bases": [],
        "keep_docstring": True,
    },
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
        import tomllib
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

        final_cfg["masking"] = DEFAULTS["masking"].copy()
        final_cfg["masking"].update(user_cfg.get("masking", {}) or {})

        whitelist_section = user_cfg.get("whitelist", {})
        if isinstance(whitelist_section, list):
            final_cfg["whitelist"] = whitelist_section
            final_cfg["whitelist_documented"] = {}
            final_cfg["whitelist_temporary"] = {}
            final_cfg["lower_confidence"] = []

        elif isinstance(whitelist_section, dict):
            final_cfg["whitelist"] = whitelist_section.get("names", [])
            final_cfg["whitelist_documented"] = whitelist_section.get("documented", {})
            final_cfg["whitelist_temporary"] = whitelist_section.get("temporary", {})
            final_cfg["lower_confidence"] = whitelist_section.get(
                "lower_confidence", []
            )

        final_cfg["overrides"] = user_cfg.get("overrides", {})

        return final_cfg

    except Exception:
        return DEFAULTS.copy()


def is_path_excluded(filepath, cfg):
    exclude = cfg.get("exclude", [])
    filepath_str = str(filepath).replace("\\", "/")

    for pattern in exclude:
        pattern = pattern.replace("\\", "/")

        if fnmatch.fnmatch(filepath_str, pattern):
            return True

        if "/" not in pattern:
            parts = filepath_str.split("/")
            for part in parts:
                if fnmatch.fnmatch(part, pattern):
                    return True

        if filepath_str.endswith("/" + pattern) or filepath_str.endswith(pattern):
            return True

    return False


def is_whitelisted(name, filepath, cfg):
    import datetime

    for pattern, config in cfg.get("whitelist_temporary", {}).items():
        if fnmatch.fnmatch(name, pattern):
            expires = config.get("expires")
            reason = config.get("reason", "temporary whitelist")

            if expires:
                try:
                    exp_date = datetime.date.fromisoformat(expires)
                    if datetime.date.today() > exp_date:
                        continue
                except ValueError:
                    pass

            return True, f"{reason} (expires: {expires})", 0

    for pattern, reason in cfg.get("whitelist_documented", {}).items():
        if fnmatch.fnmatch(name, pattern):
            return True, reason, 0

    for pattern in cfg.get("whitelist", []):
        if fnmatch.fnmatch(name, pattern):
            return True, f"matches '{pattern}'", 0

    if filepath:
        filepath_str = str(filepath).replace("\\", "/")
        for path_pattern, rules in cfg.get("overrides", {}).items():
            path_pattern = path_pattern.replace("\\", "/")
            if fnmatch.fnmatch(filepath_str, f"*{path_pattern}") or fnmatch.fnmatch(
                filepath_str, path_pattern
            ):
                for pattern in rules.get("whitelist", []):
                    if fnmatch.fnmatch(name, pattern):
                        return True, f"per-file: {path_pattern}", 0

    for pattern in cfg.get("lower_confidence", []):
        if fnmatch.fnmatch(name, pattern):
            return False, f"lower_confidence '{pattern}'", 30

    return False, None, 0


def get_expired_whitelists(cfg):
    import datetime

    expired = []
    today = datetime.date.today()

    for pattern, config in cfg.get("whitelist_temporary", {}).items():
        expires = config.get("expires")
        reason = config.get("reason", "")

        if expires:
            try:
                exp_date = datetime.date.fromisoformat(expires)
                if today > exp_date:
                    expired.append((pattern, reason, expires))
            except ValueError:
                pass

    return expired


def get_all_ignore_lines(source):
    ignore_lines = set()
    in_ignore_block = False

    for i, line in enumerate(source.splitlines(), start=1):
        line_lower = line.lower()

        if (
            "# skylos: ignore-start" in line_lower
            or "# skylos:ignore-start" in line_lower
        ):
            in_ignore_block = True
            ignore_lines.add(i)
            continue
        elif (
            "# skylos: ignore-end" in line_lower or "# skylos:ignore-end" in line_lower
        ):
            in_ignore_block = False
            ignore_lines.add(i)
            continue
        elif in_ignore_block:
            ignore_lines.add(i)
            continue

        if any(
            marker in line_lower
            for marker in [
                "# skylos: ignore",
                "# skylos:ignore",
                "#skylos: ignore",
                "#skylos:ignore",
                "# noqa: skylos",
                "pragma: no skylos",
            ]
        ):
            ignore_lines.add(i)
            stripped = line.strip()
            if stripped.startswith("@"):
                ignore_lines.add(i + 1)

    return ignore_lines


def suggest_pattern(name):
    if name.startswith("handle_"):
        return "handle_*"
    if name.startswith("on_"):
        return "on_*"
    if name.startswith("test_"):
        return "test_*"
    if name.endswith("_handler"):
        return "*_handler"
    if name.endswith("_callback"):
        return "*_callback"
    if name.endswith("Plugin"):
        return "*Plugin"
    if name.endswith("Handler"):
        return "*Handler"
    if name.endswith("Factory"):
        return "*Factory"
    return name
