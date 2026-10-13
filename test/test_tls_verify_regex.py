from skylos.rules.quality.regression import detect_security_regressions


def _diff(removed, added):
    lines = [f"@@ -1,{max(len(removed), 1)} +1,{max(len(added), 1)} @@"]
    lines += ["-" + line for line in removed]
    lines += ["+" + line for line in added]
    return "\n".join(lines) + "\n"


def _tls_messages(findings):
    return [f.get("message", "") for f in findings if "TLS" in f.get("message", "")]


def test_requests_verify_false_is_reported():
    findings = detect_security_regressions(
        _diff([], ["resp = requests.get(url, verify=False)"]), "app/client.py"
    )
    assert _tls_messages(findings)


def test_verify_downgrade_is_reported():
    findings = detect_security_regressions(
        _diff(["resp = requests.get(url, verify=True)"], ["resp = requests.get(url, verify=False)"]),
        "app/client.py",
    )
    assert any("downgraded" in message for message in _tls_messages(findings))


def test_session_attribute_and_ssl_prefix_are_reported():
    for line in ("session.verify = False", "client = Client(ssl_verify=False)"):
        assert _tls_messages(detect_security_regressions(_diff([], [line]), "app/client.py")), line


def test_other_flags_ending_in_verify_are_not_tls():
    for line in ("result = analyze(path, grep_verify=False)", "run(reverify=False)"):
        assert not _tls_messages(detect_security_regressions(_diff([], [line]), "app/tool.py")), line
