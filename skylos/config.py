from pathlib import Path
import fnmatch
import copy

DEFAULTS = {
    "complexity": 10,
    "nesting": 3,
    "max_args": 5,
    "max_lines": 50,
    "god_file_max_lines": 500,
    "god_file_max_definitions": 40,
    "god_file_max_top_level_definitions": 25,
    "duplicate_strings": 3,
    "security_contracts": [],
    "ignore": [],
    "exclude": [],
    "whitelist": [],
    "whitelist_documented": {},
    "whitelist_temporary": {},
    "lower_confidence": [],
    "overrides": {},
    "non_library_dirs": {},
    "nudges": True,
    "check_circular": True,
    "max_circular_deps": -1,
    "architecture": {
        "strict": False,
        "enforce_iad": False,
        "layers": [],
        "rules": [],
    },
    "masking": {
        "names": [],
        "decorators": [],
        "bases": [],
        "keep_docstring": True,
    },
    "templates": {
        "security": None,
        "quality": None,
        "security_audit": None,
        "review": None,
    },
    "vibe": {
        "extra_phantom_names": [],
        "extra_phantom_decorators": [],
        "extra_credential_names": [],
        "extra_credential_suffixes": [],
        "extra_secret_names": [],
        "extra_security_var_keywords": [],
        "extra_well_known_env_vars": [],
        "extra_sensitive_file_keywords": [],
        "extra_placeholder_values": [],
        "extra_network_timeout_calls": [],
    },
}


_INT_CONFIG_KEYS = {
    "complexity": 1,
    "nesting": 1,
    "max_args": 1,
    "max_lines": 1,
    "god_file_max_lines": 1,
    "god_file_max_definitions": 1,
    "god_file_max_top_level_definitions": 1,
    "duplicate_strings": 1,
    "max_circular_deps": -1,
}
_STRING_LIST_CONFIG_KEYS = {
    "ignore",
    "exclude",
    "whitelist",
    "lower_confidence",
}
_DICT_CONFIG_KEYS = {
    "overrides",
    "non_library_dirs",
    "whitelist_documented",
    "whitelist_temporary",
}
_BOOL_CONFIG_KEYS = {
    "nudges",
    "check_circular",
}


def load_config(start_path) -> dict:
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent

    root_config, sync_config = _find_config_paths(current)
    final_cfg = copy.deepcopy(DEFAULTS)

    if sync_config:
        final_cfg = _merge_user_config(final_cfg, _load_synced_config(sync_config))

    if not root_config:
        return final_cfg

    try:
        return _merge_user_config(final_cfg, _load_pyproject_user_config(root_config))
    except Exception:
        return final_cfg


def _is_safe_config_file(config_path: Path, expected_name: str) -> bool:
    if not isinstance(config_path, Path):
        return False
    if config_path.name != expected_name:
        return False
    if config_path.is_symlink() or not config_path.is_file():
        return False
    try:
        config_path.resolve(strict=True)
    except OSError:
        return False
    return True


def _find_config_paths(start_dir: Path) -> tuple[Path | None, Path | None]:
    current = start_dir
    root_config = None
    sync_config = None

    while True:
        sync_path = current / ".skylos" / "config.yaml"
        if sync_config is None and sync_path.exists():
            sync_config = sync_path

        toml_path = current / "pyproject.toml"
        if toml_path.exists():
            root_config = toml_path
            break

        if current.parent == current:
            break
        current = current.parent

    return root_config, sync_config


def _load_pyproject_user_config(root_config: Path) -> dict:
    if not _is_safe_config_file(root_config, "pyproject.toml"):
        return {}

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return {}

    with root_config.open("rb") as f:
        data = tomllib.load(f)

    user_cfg = dict(data.get("tool", {}).get("skylos", {}) or {})
    gate_cfg = data.get("tool", {}).get("skylos", {}).get("gate", {})
    if gate_cfg:
        user_cfg["gate"] = gate_cfg
    return user_cfg


def _load_synced_config(sync_config: Path) -> dict:
    if not _is_safe_config_file(sync_config, "config.yaml"):
        return {}

    try:
        import yaml
    except ImportError:
        return {}

    try:
        raw = yaml.safe_load(sync_config.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

    if not isinstance(raw, dict):
        return {}

    normalized = dict(raw)
    alias_map = {
        "complexity_threshold": "complexity",
        "nesting_threshold": "nesting",
        "arg_count_threshold": "max_args",
        "function_length_threshold": "max_lines",
        "exclude_paths": "exclude",
        "prompt_templates": "templates",
        "vibe_dictionary": "vibe",
    }
    for source_key, target_key in alias_map.items():
        if source_key in raw and target_key not in normalized:
            normalized[target_key] = raw[source_key]

    if "gate" not in normalized:
        gate_cfg = {}
        if "gate_enabled" in raw:
            gate_cfg["enabled"] = raw.get("gate_enabled")
        if "gate_mode" in raw:
            gate_cfg["mode"] = raw.get("gate_mode")
        if gate_cfg:
            normalized["gate"] = gate_cfg

    return normalized


def _merge_user_config(base_cfg: dict, user_cfg: dict | None) -> dict:
    if not isinstance(user_cfg, dict):
        return _sanitize_config(base_cfg)

    final_cfg = copy.deepcopy(base_cfg)

    for key, value in user_cfg.items():
        if key == "whitelist":
            continue
        if key == "masking":
            if isinstance(value, dict):
                merged_masking = copy.deepcopy(DEFAULTS["masking"])
                current_masking = final_cfg.get("masking")
                if isinstance(current_masking, dict):
                    merged_masking.update(current_masking)
                merged_masking.update(value)
                final_cfg["masking"] = merged_masking
            continue
        if key in ("gate", "templates", "vibe", "architecture") and isinstance(
            value, dict
        ):
            merged_section = {}
            current_section = final_cfg.get(key)
            if isinstance(current_section, dict):
                merged_section.update(current_section)
            merged_section.update(value)
            final_cfg[key] = merged_section
            continue
        final_cfg[key] = value

    whitelist_section = user_cfg.get("whitelist")
    if isinstance(whitelist_section, list):
        final_cfg["whitelist"] = whitelist_section
        final_cfg["whitelist_documented"] = {}
        final_cfg["whitelist_temporary"] = {}
        final_cfg["lower_confidence"] = []
    elif isinstance(whitelist_section, dict):
        final_cfg["whitelist"] = whitelist_section.get("names", [])
        final_cfg["whitelist_documented"] = whitelist_section.get("documented", {})
        final_cfg["whitelist_temporary"] = whitelist_section.get("temporary", {})
        final_cfg["lower_confidence"] = whitelist_section.get("lower_confidence", [])

    if "overrides" in user_cfg:
        final_cfg["overrides"] = user_cfg.get("overrides", {})
    if "non_library_dirs" in user_cfg:
        final_cfg["non_library_dirs"] = user_cfg.get("non_library_dirs", {})

    return _sanitize_config(final_cfg)


def _sanitize_config(cfg: dict) -> dict:
    safe = copy.deepcopy(cfg) if isinstance(cfg, dict) else copy.deepcopy(DEFAULTS)

    for key, minimum in _INT_CONFIG_KEYS.items():
        safe[key] = _safe_int(safe.get(key), DEFAULTS[key], minimum=minimum)

    for key in _STRING_LIST_CONFIG_KEYS:
        safe[key] = _safe_string_list(safe.get(key), DEFAULTS[key])

    for key in _DICT_CONFIG_KEYS:
        safe[key] = _safe_dict(safe.get(key), DEFAULTS[key])

    for key in _BOOL_CONFIG_KEYS:
        safe[key] = _safe_bool(safe.get(key), DEFAULTS[key])

    safe["security_contracts"] = _safe_dict_list(
        safe.get("security_contracts"), DEFAULTS["security_contracts"]
    )
    safe["masking"] = _sanitize_masking_section(safe.get("masking"))
    safe["templates"] = _sanitize_templates_section(safe.get("templates"))
    safe["vibe"] = _sanitize_vibe_section(safe.get("vibe"))
    safe["architecture"] = _sanitize_architecture_section(safe.get("architecture"))

    if "gate" in safe and not isinstance(safe.get("gate"), dict):
        safe["gate"] = {}

    return safe


def _safe_int(value, default, *, minimum: int | None = None):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    if minimum is not None and value < minimum:
        return default
    return value


def _safe_bool(value, default):
    return value if isinstance(value, bool) else default


def _safe_string_list(value, default):
    if not isinstance(value, list):
        return copy.deepcopy(default)
    return [item for item in value if isinstance(item, str)]


def _safe_dict(value, default):
    return copy.deepcopy(value) if isinstance(value, dict) else copy.deepcopy(default)


def _safe_dict_list(value, default):
    if not isinstance(value, list):
        return copy.deepcopy(default)
    return [copy.deepcopy(item) for item in value if isinstance(item, dict)]


def _sanitize_masking_section(value):
    raw = value if isinstance(value, dict) else {}
    safe = copy.deepcopy(DEFAULTS["masking"])
    safe["names"] = _safe_string_list(raw.get("names"), safe["names"])
    safe["decorators"] = _safe_string_list(raw.get("decorators"), safe["decorators"])
    safe["bases"] = _safe_string_list(raw.get("bases"), safe["bases"])
    safe["keep_docstring"] = _safe_bool(
        raw.get("keep_docstring"), safe["keep_docstring"]
    )
    return safe


def _sanitize_templates_section(value):
    raw = value if isinstance(value, dict) else {}
    safe = copy.deepcopy(DEFAULTS["templates"])
    for key in list(safe):
        candidate = raw.get(key)
        if candidate is None or isinstance(candidate, str):
            safe[key] = candidate
    return safe


def _sanitize_vibe_section(value):
    raw = value if isinstance(value, dict) else {}
    safe = copy.deepcopy(DEFAULTS["vibe"])
    for key in list(safe):
        safe[key] = _safe_string_list(raw.get(key), safe[key])
    return safe


def _sanitize_architecture_section(value):
    raw = value if isinstance(value, dict) else {}
    safe = copy.deepcopy(DEFAULTS["architecture"])
    for key in ("strict", "enforce_iad", "strict_iad"):
        if key in raw:
            safe[key] = _safe_bool(raw.get(key), safe.get(key, False))
    safe["layers"] = _safe_dict_list(raw.get("layers"), safe["layers"])
    safe["rules"] = _safe_dict_list(raw.get("rules"), safe["rules"])
    return safe


def is_path_excluded(filepath, cfg) -> bool:
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


def is_whitelisted(name, filepath, cfg) -> tuple[bool, str | None, int]:
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


def get_expired_whitelists(cfg) -> list[tuple[str, str, str]]:
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


def get_all_ignore_lines(source) -> set[int]:
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
                "# noqa",
                "#noqa",
            ]
        ):
            ignore_lines.add(i)
            stripped = line.strip()
            if stripped.startswith("@"):
                ignore_lines.add(i + 1)

    return ignore_lines


def suggest_pattern(name) -> str | None:
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
