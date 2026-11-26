"""SKY-D413 checks local Envoy bootstrap declarations without proxy traffic."""

from textwrap import dedent

import pytest

from skylos.rules.config.registry import scan_config_files

BOOTSTRAP = dedent("""\
    static_resources:
      listeners:
      - name: ingress
        address:
          socket_address: {address: 127.0.0.1, port_value: 10000}
        filter_chains:
        - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: ingress
              codec_type: AUTO
              http_protocol_options:
                allow_chunked_length: true
              route_config: {name: local, virtual_hosts: []}
              http_filters:
              - name: envoy.filters.http.router
                typed_config:
                  '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    """)


def _matches(root, **kwargs):
    return [f for f in scan_config_files(root, **kwargs) if f["rule_id"] == "SKY-D413"]


def test_envoy_bootstrap_reaches_normal_config_scan(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(BOOTSTRAP)
    (finding,) = _matches(tmp_path)
    assert finding["provider"] == "envoy"
    assert finding["severity"] == "MEDIUM"
    assert finding["metadata"]["review_required"] is True
    assert finding["file"] == str(path)
    assert (
        BOOTSTRAP.splitlines()[finding["line"] - 1].strip()
        == "allow_chunked_length: true"
    )
    assert _matches(path, ignore={"SKY-D413"}) == []
    assert _matches(tmp_path, changed_files={"README.md"}) == []
    assert _matches(tmp_path, scan_paths=[str(tmp_path / "unrelated")]) == []


def test_default_chain_and_camel_case_are_effective_settings(tmp_path):
    path = tmp_path / "proxy.yml"
    text = BOOTSTRAP.replace(
        "filter_chains:\n    - filters:", "defaultFilterChain:\n      filters:"
    )
    text = text.replace("static_resources", "staticResources").replace(
        "typed_config", "typedConfig"
    )
    text = text.replace("http_protocol_options", "httpProtocolOptions")
    text = text.replace("allow_chunked_length", "allowChunkedLength")
    path.write_text(text)
    (finding,) = _matches(path)
    assert finding["metadata"]["config_path"][-1] == "allowChunkedLength"


@pytest.mark.parametrize(
    "line", ["", "codec_type: HTTP1", "codec_type: 0", "codecType: 1"]
)
def test_proto_default_and_http1_codec_enum_values(tmp_path, line):
    path = tmp_path / "envoy.yaml"
    path.write_text(BOOTSTRAP.replace("codec_type: AUTO", line))
    assert len(_matches(path)) == 1


@pytest.mark.parametrize(
    "old,new",
    [
        ("allow_chunked_length: true", "enable_trailers: true"),
        ("allow_chunked_length: true", "allow_chunked_length: false"),
        ("allow_chunked_length: true", 'allow_chunked_length: "true"'),
        (
            "allow_chunked_length: true",
            "allow_chunked_length: true\n            allow_chunked_length: false",
        ),
        (
            "allow_chunked_length: true",
            "allow_chunked_length: true\n            allowChunkedLength: false",
        ),
        ("codec_type: AUTO", "codec_type: HTTP2"),
        ("codec_type: AUTO", "codecType: HTTP3"),
        ("codec_type: AUTO", "codec_type: 2"),
        ("codec_type: AUTO", "codec_type: 3"),
        ("codec_type: AUTO", "codec_type: true"),
        ("codec_type: AUTO", "codec_type: AUTO\n          codecType: HTTP3"),
        ("port_value: 10000", "port_value: 10000, protocol: UDP"),
        ("port_value: 10000", "port_value: 10000, protocol: 1"),
        (
            "filter_chains:",
            "udp_listener_config: {quic_options: {}}\n    filter_chains:",
        ),
        ("static_resources:", "example:"),
        ("filter_chains:", "metadata:"),
        ("http_protocol_options:", "http2_protocol_options:"),
        ("v3.HttpConnectionManager", "v3.OtherFilter"),
    ],
)
def test_ambiguous_inactive_and_unrelated_declarations_stay_quiet(tmp_path, old, new):
    path = tmp_path / "envoy.yml"
    path.write_text(BOOTSTRAP.replace(old, new))
    assert _matches(path) == []


def _mounted_manifest(*, workload="Pod", renamed=False, bootstrap=BOOTSTRAP):
    from textwrap import indent


    key = "bootstrap.yaml" if renamed else "envoy.yaml"
    name = "edge-config"
    source = {"name": name}
    if renamed:
        source["items"] = [{"key": key, "path": "envoy.yaml"}]
    spec = {
        "containers": [
            {
                "name": "edge",
                "image": "envoyproxy/envoy:v1.35.0",
                "args": ["-c", "/etc/envoy/envoy.yaml"],
                "volumeMounts": [{"name": "conf", "mountPath": "/etc/envoy"}],
            }
        ],
        "volumes": [{"name": "conf", "configMap": source}],
    }
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"namespace": "shop", "name": "edge"},
        "spec": spec,
    }
    if workload == "Deployment":
        doc.update(
            apiVersion="apps/v1",
            kind=workload,
            spec={
                "selector": {"matchLabels": {"app": "edge"}},
                "template": {"metadata": {"labels": {"app": "edge"}}, "spec": spec},
            },
        )
    cm = (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: edge-config, namespace: shop}\n"
        f"data:\n  {key}: |\n" + indent(bootstrap, "    ")
    )
    return cm, doc


@pytest.mark.parametrize("kind,renamed", [("Pod", False), ("Deployment", True)])
def test_declared_envoy_mount_resolves_to_literal_config_line(tmp_path, kind, renamed):
    import yaml

    cm, doc = _mounted_manifest(workload=kind, renamed=renamed)
    source = cm + "---\n" + yaml.safe_dump(doc)
    (tmp_path / "combined.yaml").write_text(source)
    (finding,) = _matches(tmp_path, changed_files={"combined.yaml"})
    assert (
        source.splitlines()[finding["line"] - 1].strip() == "allow_chunked_length: true"
    )
    assert finding["metadata"]["workload"] == "edge"
    assert finding["metadata"]["config_map_key"] == (
        "bootstrap.yaml" if renamed else "envoy.yaml"
    )


@pytest.mark.parametrize(
    "case",
    [
        "different_namespace",
        "different_mount",
        "different_file",
        "other_image",
        "other_process",
        "override",
        "different_container",
        "duplicate_volume",
        "duplicate_map",
        "split_files",
        "disabled",
        "duplicate_option",
        "ambiguous_paths",
        "subpath",
        "relative",
        "no_workload",
    ],
)
def test_unproven_mount_or_setting_stays_quiet(tmp_path, case):
    import yaml

    bootstrap = BOOTSTRAP
    if case == "disabled":
        bootstrap = bootstrap.replace(
            "allow_chunked_length: true", "allow_chunked_length: false"
        )
    if case == "duplicate_option":
        bootstrap = bootstrap.replace(
            "allow_chunked_length: true",
            "allow_chunked_length: false\n            allow_chunked_length: true",
        )
    cm, doc = _mounted_manifest(renamed=True, bootstrap=bootstrap)
    pod = doc["spec"]
    container = pod["containers"][0]
    mount = container["volumeMounts"][0]
    if case == "different_namespace":
        doc["metadata"]["namespace"] = "other"
    elif case == "different_mount":
        mount["mountPath"] = "/var/lib/conf"
    elif case == "different_file":
        container["args"][-1] = "/etc/envoy/unused.yaml"
    elif case == "other_image":
        container["image"] = "example.org/envoyproxy/envoy:v1.35.0"
    elif case == "other_process":
        container["command"] = ["config-inspector"]
    elif case == "override":
        container["args"] += ["--config-yaml", "{}"]
    elif case == "different_container":
        pod["containers"].append(
            {
                "name": "logs",
                "image": "example.org/logger",
                "volumeMounts": container.pop("volumeMounts"),
            }
        )
    elif case == "duplicate_volume":
        pod["volumes"].append({"name": "conf", "emptyDir": {}})
    elif case == "duplicate_map":
        cm += "---\n" + cm
    elif case == "split_files":
        (tmp_path / "config.yaml").write_text(cm)
        cm = ""
    elif case == "ambiguous_paths":
        pod["volumes"][0]["configMap"]["items"].append(
            {"path": "envoy.yaml", "key": "unused"}
        )
    elif case == "subpath":
        mount["subPathExpr"] = "$(ENV)"
    elif case == "relative":
        container["args"][-1] = "envoy.yaml"
    tail = "" if case == "no_workload" else "---\n" + yaml.safe_dump(doc)
    (tmp_path / "deployment.yaml").write_text(cm + tail)
    assert not _matches(tmp_path)


def test_literal_argv_and_binary_key_conflict(tmp_path):
    import yaml

    cm, doc = _mounted_manifest()
    container = doc["spec"]["containers"][0]
    container["command"] = ["/usr/local/bin/envoy"]
    container["args"] = ["--config-path=/etc/envoy/envoy.yaml"]
    path = tmp_path / "manifest.yaml"
    tail = "---\n" + yaml.safe_dump(doc)
    path.write_text(cm + tail)
    assert len(_matches(tmp_path)) == 1
    path.write_text(cm + "binaryData: {envoy.yaml: 'e30='}\n" + tail)
    assert _matches(tmp_path) == []
