from textwrap import dedent

import pytest

from skylos.visitors.languages.rust import scan_rust_file


def settings(tmp_path, code):
    path = tmp_path / "src/lib.rs"
    path.parent.mkdir(exist_ok=True)
    path.write_text(dedent(code).strip(), encoding="utf-8")
    return [
        (f["line"], f["message"])
        for f in scan_rust_file(str(path), {})[7]
        if f["rule_id"] == "SKY-D210"
    ]


def test_reqwest_reports_the_setting_that_disabled_each_check(tmp_path):
    rows = settings(
        tmp_path,
        """
        use reqwest::blocking::Client as Http;
        const ACCEPT: bool = true;
        fn client() {
            let accept = ACCEPT;
            let _ = Http::builder()
                .tls_danger_accept_invalid_certs(/* intentional */ accept)
                .tls_danger_accept_invalid_hostnames(true)
                .build();
        }
    """,
    )
    assert [line for line, _ in rows] == [6, 7]
    assert "certificate-chain" in rows[0][1]
    assert "hostname" in rows[1][1]


def test_mutable_switch_unknown_values_and_shadows_stay_quiet(tmp_path):
    assert (
        settings(
            tmp_path,
            """
        struct Local;
        impl Local { fn danger_accept_invalid_certs(&self, _: bool) {} }
        fn settings(builder: reqwest::ClientBuilder, enabled: bool) {
            let mut switch = true;
            change(&mut switch);
            let _ = builder.danger_accept_invalid_certs(switch)
                .tls_danger_accept_invalid_certs(enabled)
                .tls_danger_accept_invalid_hostnames(false);
            Local.danger_accept_invalid_certs(true);
        }
        fn change(flag: &mut bool) { *flag = false; }
    """,
        )
        == []
    )


@pytest.mark.parametrize(
    ("kind", "option"),
    [
        ("curl::easy::Easy", "ssl_verify_host"),
        ("curl::easy::Easy2<H>", "ssl_verify_peer"),
    ],
)
def test_curl_only_flags_a_disabled_check(tmp_path, kind, option):
    parameter = "<H: curl::easy::Handler>" if "Easy2" in kind else ""
    rows = settings(
        tmp_path,
        f"""
        fn configure{parameter}(handle: &mut {kind}, incoming: bool) {{
            let _ = handle.{option}(true);
            let _ = handle.{option}(incoming);
            let _ = handle.{option}(false);
        }}
    """,
    )
    assert [line for line, _ in rows] == [4]
    assert option in rows[0][1]


def test_qualified_curl_constructor_and_setter_use_the_handle_type(tmp_path):
    rows = settings(
        tmp_path,
        """
        use curl::easy::Easy2 as Handle;
        fn configure<H: curl::easy::Handler>(sink: H) {
            let mut h = Handle::<H>::new(sink);
            let _ = Handle::<H>::ssl_verify_peer(&mut h, false);
        }
    """,
    )
    assert [line for line, _ in rows] == [4]


def test_native_tls_setter_chain_and_test_exclusion(tmp_path):
    rows = settings(
        tmp_path,
        """
        use native_tls::TlsConnector;
        pub fn client() {
            TlsConnector::builder().use_sni(true)
                .danger_accept_invalid_hostnames(true);
        }
        #[cfg(test)]
        mod tests {
            fn fixture() { reqwest::Client::builder().tls_danger_accept_invalid_certs(true); }
        }
    """,
    )
    assert [line for line, _ in rows] == [4]


def test_tls_branch_overwrites_and_mutable_borrows(tmp_path):
    rows = settings(
        tmp_path,
        """
        fn configure(choice: bool) {
            let mut mixed = false;
            if choice { mixed = true; }
            let _ = reqwest::Client::builder().danger_accept_invalid_certs(mixed);
            let mut overwritten = true;
            overwritten = false;
            let _ = reqwest::Client::builder().danger_accept_invalid_certs(overwritten);
            let mut escaped = true;
            change(&mut escaped);
            let _ = reqwest::Client::builder().danger_accept_invalid_certs(escaped);
            let impossible = if false { true } else { false };
            let _ = reqwest::Client::builder().danger_accept_invalid_certs(impossible);
        }
        fn change(value: &mut bool) { *value = false; }
    """,
    )
    assert [line for line, _ in rows] == [4]
    assert "can disable" in rows[0][1]


def test_local_boolean_callers_must_reach_the_setting(tmp_path):
    rows = settings(
        tmp_path,
        """
        fn first(flag: bool) {
            let enabled = flag;
            reqwest::Client::builder().danger_accept_invalid_certs(enabled);
        }
        fn guarded(flag: bool) {
            if flag { return; }
            reqwest::Client::builder().danger_accept_invalid_certs(flag);
        }
        fn test_only(flag: bool) {
            reqwest::Client::builder().danger_accept_invalid_certs(flag);
        }
        fn only_safe(flag: bool) { reqwest::Client::builder().danger_accept_invalid_certs(flag); }
        fn dormant(flag: bool) { reqwest::Client::builder().danger_accept_invalid_certs(flag); }
        fn maybe(flag: bool) { reqwest::Client::builder().danger_accept_invalid_certs(flag); }
        fn run(input: bool) {
            first(false);
            first(true);
            guarded(true);
            only_safe(false);
            let _ = || dormant(true);
            maybe(input);
        }
        #[test] fn exercise() { test_only(true); }
    """,
    )
    assert [line for line, _ in rows] == [3]


def test_filesystem_controls_need_a_resolved_filesystem_api(tmp_path):
    rows = settings(
        tmp_path,
        """
        use std::fs as fs;
        fn run(path: &std::path::Path, custom: &Local) -> std::io::Result<()> {
            let enabled = fs::exists(path)?;
            reqwest::Client::builder().danger_accept_invalid_certs(enabled);
            let disk = path.metadata()?.is_file();
            reqwest::Client::builder().danger_accept_invalid_hostnames(disk);
            reqwest::Client::builder().danger_accept_invalid_certs(custom.is_file());
            Ok(())
        }
        struct Local;
        impl Local { fn is_file(&self) -> bool { false } }
    """,
    )
    assert [line for line, _ in rows] == [4, 6]
    assert all("can disable" in message for _, message in rows)


def test_standard_input_must_supply_the_boolean(tmp_path):
    rows = settings(
        tmp_path,
        """
        fn run() -> std::io::Result<()> {
            let mut input = String::new();
            let other = String::new();
            std::io::stdin().read_line(&mut input)?;
            let incoming = input.trim().parse::<bool>().unwrap_or(false);
            reqwest::Client::builder().danger_accept_invalid_hostnames(incoming);
            let safe = other.trim().parse::<bool>().unwrap_or(false);
            reqwest::Client::builder().danger_accept_invalid_hostnames(safe);
            input.clear();
            let cleared = input.parse::<bool>().unwrap_or(false);
            reqwest::Client::builder().danger_accept_invalid_hostnames(cleared);
            Ok(())
        }
    """,
    )
    assert [line for line, _ in rows] == [6]


def test_unreachable_tls_controls_remain_quiet(tmp_path):
    rows = settings(
        tmp_path,
        """
        async fn deferred(flag: bool) { reqwest::Client::builder().danger_accept_invalid_certs(flag); }
        fn test_setting(flag: bool) {
            #[cfg(test)]
            reqwest::Client::builder().danger_accept_invalid_certs(flag);
        }
        fn run(path: &std::path::Path) -> std::io::Result<()> {
            let _future = deferred(true);
            test_setting(true);
            let switch = path.is_file();
            if switch { return Ok(()); }
            reqwest::Client::builder().danger_accept_invalid_certs(switch);
            let mut fixed = false;
            while false { fixed = true; }
            reqwest::Client::builder().danger_accept_invalid_certs(fixed);
            let mut input = String::from("not-a-boolean:");
            std::io::stdin().read_line(&mut input)?;
            let invalid = input.parse::<bool>().unwrap_or(false);
            reqwest::Client::builder().danger_accept_invalid_certs(invalid);
            Ok(())
        }
    """,
    )
    assert rows == []
