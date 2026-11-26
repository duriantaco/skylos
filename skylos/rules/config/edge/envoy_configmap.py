"""Link a Kubernetes Envoy container to a bootstrap in the same manifest file."""

import re
from pathlib import PurePosixPath

from skylos.rules.config.kubernetes.model import embedded_mapping

_IMAGE = re.compile(
    r"(?:docker\.io/)?envoyproxy/envoy(?::[\w][\w.-]*)?(?:@sha256:[0-9a-f]{64})?"
)
_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
_KEY = re.compile(r"[A-Za-z0-9._-]+")


def _literal_path(value, *, absolute):
    if not isinstance(value, str) or not value or value.startswith("/") != absolute:
        return None
    if not all(
        _KEY.fullmatch(part) and part not in {".", ".."}
        for part in value.removeprefix("/").split("/")
    ):
        return None
    return PurePosixPath(value)


def _bootstrap_path(container):
    image = container.get("image")
    if not isinstance(image, str) or not _IMAGE.fullmatch(image):
        return None
    command = container.get("command", [])
    args = container.get("args", [])
    if not isinstance(command, list) or not isinstance(args, list):
        return None
    if command and command[0] not in ("envoy", "/usr/local/bin/envoy"):
        return None
    argv = command[1:] + args
    if len(argv) == 2 and argv[0] in ("-c", "--config-path"):
        return _literal_path(argv[1], absolute=True)
    if (
        len(argv) == 1
        and isinstance(argv[0], str)
        and argv[0].startswith("--config-path=")
    ):
        return _literal_path(argv[0].removeprefix("--config-path="), absolute=True)
    return None


def _volume_key(config, relative):
    if "items" not in config:
        return str(relative) if len(relative.parts) == 1 else None
    items = config["items"]
    if not isinstance(items, list):
        return None
    destinations = {}
    for item in items:
        if not isinstance(item, dict):
            return None
        key = item.get("key")
        path = _literal_path(item.get("path"), absolute=False)
        if (
            not isinstance(key, str)
            or not _KEY.fullmatch(key)
            or not path
            or path in destinations
        ):
            return None
        destinations[path] = key
    return destinations.get(relative)


def _mounted_key(container, volumes):
    target = _bootstrap_path(container)
    mounts = container.get("volumeMounts")
    if not target or not isinstance(mounts, list):
        return None
    candidates = []
    for mount in mounts:
        if not isinstance(mount, dict):
            return None
        base = _literal_path(mount.get("mountPath"), absolute=True)
        if base is None:
            return None
        if target.is_relative_to(base):
            candidates.append((mount, target.relative_to(base)))
    if len(candidates) != 1:
        return None
    mount, relative = candidates[0]
    volume_name = mount.get("name")
    if "subPath" in mount or "subPathExpr" in mount or not isinstance(volume_name, str):
        return None
    volume = volumes.get(volume_name)
    if not volume or set(volume) != {"name", "configMap"}:
        return None
    config = volume["configMap"]
    if not isinstance(config, dict) or not isinstance(config.get("name"), str):
        return None
    key = _volume_key(config, relative)
    if key:
        return config["name"], key
    return None


def _references(spec):
    if not isinstance(spec, dict):
        return
    volumes, containers = spec.get("volumes"), spec.get("containers")
    if not isinstance(volumes, list) or not isinstance(containers, list):
        return
    by_name = {}
    for volume in volumes:
        if not isinstance(volume, dict) or not isinstance(volume.get("name"), str):
            return
        name = volume["name"]
        by_name[name] = None if name in by_name else volume
    for container in containers:
        if isinstance(container, dict):
            reference = _mounted_key(container, by_name)
            if reference:
                yield reference


def mounted_bootstraps(manifests):
    config_maps = {}
    references = {}
    for manifest in manifests:
        data = manifest.data
        resource = data.get("apiVersion"), data.get("kind")
        metadata = data.get("metadata")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str):
            continue
        name, namespace = metadata["name"], metadata.get("namespace", "")
        if (
            not _NAME.fullmatch(name)
            or not isinstance(namespace, str)
            or (namespace and not _NAME.fullmatch(namespace))
        ):
            continue
        if resource == ("v1", "ConfigMap"):
            identity = manifest.file, namespace, name
            config_maps[identity] = None if identity in config_maps else manifest
        elif resource in (("v1", "Pod"), ("apps/v1", "Deployment")):
            spec = data.get("spec")
            if resource[1] == "Deployment" and isinstance(spec, dict):
                template = spec.get("template")
                spec = template.get("spec") if isinstance(template, dict) else None
            for config_name, key in _references(spec):
                references.setdefault(
                    (manifest.file, namespace, config_name, key), name
                )
    for (file, namespace, name, key), workload in references.items():
        manifest = config_maps.get((file, namespace, name))
        if manifest is None:
            continue
        data = manifest.data.get("data")
        binary = manifest.data.get("binaryData", {})
        if not isinstance(binary, dict) or key in binary:
            continue
        text = data.get(key) if isinstance(data, dict) else None
        if not isinstance(text, str):
            continue
        span = manifest.source.scalar_lines_for_path(
            ("data", key), literal_block_only=True
        )
        if span:
            source = embedded_mapping(text)
            if source:
                yield manifest, key, span[0], source, workload
