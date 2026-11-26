"""Review explicit downstream HTTP/1 framing settings in Envoy v3 bootstrap YAML."""

from skylos.rules.config.edge.envoy_configmap import mounted_bootstraps
from skylos.rules.config.findings import config_finding

RULE_ID = "SKY-D413"
_HCM = (
    "type.googleapis.com/envoy.extensions.filters.network."
    "http_connection_manager.v3.HttpConnectionManager"
)


def _field_key(mapping, name):
    """Protobuf JSON accepts the original field name and its lowerCamelCase form."""
    if not isinstance(mapping, dict):
        return None
    first, *rest = name.split("_")
    camel = first + "".join(word.title() for word in rest)
    if name != camel and name in mapping and camel in mapping:
        return None  # Two spellings of the same protobuf field are ambiguous.
    if name in mapping:
        return name
    return camel if camel in mapping else None


def _nodes(value, path, fields):
    """Follow the bootstrap schema. None represents one repeated protobuf field."""
    if not fields:
        yield path, value
        return
    field, *remaining = fields
    if field is None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                yield from _nodes(item, (*path, index), remaining)
    else:
        key = _field_key(value, field)
        if key is not None:
            yield from _nodes(value[key], (*path, key), remaining)


def _setting_paths(bootstrap):
    for path, listener in _nodes(
        bootstrap, (), ("static_resources", "listeners", None)
    ):
        # A UDP listener cannot process downstream HTTP/1. Envoy requires
        # additional addresses on the same listener to use the same protocol.
        if any(
            protocol == "UDP" or (type(protocol) is int and protocol == 1)
            for _, protocol in _nodes(
                listener, (), ("address", "socket_address", "protocol")
            )
        ) or any(
            isinstance(options, dict)
            for _, options in _nodes(
                listener, (), ("udp_listener_config", "quic_options")
            )
        ):
            continue
        for chains in (("filter_chains", None), ("default_filter_chain",)):
            for config_path, config in _nodes(
                listener, path, (*chains, "filters", None, "typed_config")
            ):
                if not isinstance(config, dict) or config.get("@type") != _HCM:
                    continue
                if "codec_type" in config and "codecType" in config:
                    continue
                codec = config.get("codec_type", config.get("codecType", "AUTO"))
                if codec not in ("AUTO", "HTTP1") and not (
                    type(codec) is int and codec in (0, 1)
                ):
                    continue
                for setting, enabled in _nodes(
                    config,
                    config_path,
                    ("http_protocol_options", "allow_chunked_length"),
                ):
                    if enabled is True:
                        yield setting


def _declarations(manifests):
    for manifest in manifests:
        for path in _setting_paths(manifest.data):
            yield manifest.file, manifest.line(path), {"config_path": list(path)}
    for manifest, key, header, source, workload in mounted_bootstraps(manifests):
        for path in _setting_paths(source.data):
            line = source.line_for_path(path)
            if line:
                yield manifest.file, header + line, {
                    "config_path": list(path),
                    "config_map_key": key,
                    "workload": workload,
                }


def scan_envoy_http1(manifests, *, ignore=None):
    if ignore and RULE_ID in ignore:
        return []
    findings = []
    for file, line, metadata in _declarations(manifests):
        finding = config_finding(
            rule_id=RULE_ID,
            domain="deployment",
            provider="envoy",
            name="Envoy listener configured to accept ambiguous HTTP/1 framing",
            message=(
                "This Envoy listener enables allow_chunked_length. Review whether all "
                "proxies on its HTTP/1 path agree on request framing. Remove this option "
                "to restore Envoy's default rejection of conflicting length headers."
            ),
            file=file,
            line=line,
            severity="MEDIUM",
            value="allow_chunked_length=true",
            finding_type="envoy_http1_framing",
        )
        finding["metadata"] = {"review_required": True, **metadata}
        findings.append(finding)
    return findings
