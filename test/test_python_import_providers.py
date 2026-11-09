from skylos.rules.danger.danger import scan_ctx


def test_dynamic_global_write_cannot_prove_import_provider(tmp_path):
    path = tmp_path / "server.py"
    path.write_text(
        "from importlib import import_module\nfrom flask import request\nglobals()['import_module'] = custom\nimport_module(request.args['plugin'])\n"
    )
    findings = scan_ctx(tmp_path, [path])
    assert not [f for f in findings if f["rule_id"] == "SKY-D357"]
