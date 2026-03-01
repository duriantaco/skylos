ENGINE_ID = "skylos-go"


def build_go_engine_args(engine_bin, root, skylos_version):
    return [
        engine_bin,
        "analyze",
        "--root",
        root,
        "--format",
        "json",
        "--skylos-version",
        skylos_version,
    ]


def validate_go_engine_output(obj):
    if type(obj) is not dict:
        raise ValueError("Go engine output must be a JSON object")

    if obj.get("engine") != ENGINE_ID:
        raise ValueError(
            "Go engine output has wrong engine id: %r" % (obj.get("engine"),)
        )

    version = obj.get("version")
    if type(version) is not str or not version.strip():
        raise ValueError("Go engine output missing/invalid version")

    findings = obj.get("findings")
    if type(findings) is not list:
        raise ValueError("Go engine output missing/invalid findings list")

    for f in findings:
        if type(f) is not dict:
            raise ValueError("Go engine findings must be objects")

    symbols = obj.get("symbols")
    if symbols is not None:
        if type(symbols) is not dict:
            raise ValueError("Go engine symbols must be a JSON object")
        if type(symbols.get("defs")) is not list:
            raise ValueError("Go engine symbols missing/invalid defs list")
        if type(symbols.get("refs")) is not list:
            raise ValueError("Go engine symbols missing/invalid refs list")

    return obj
