"""Three bounded Kubernetes declaration policies, with explicit uncertainty."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import posixpath

from skylos.rules.config.findings import config_finding
from skylos.rules.config.kubernetes.model import load_project


SUPPORTED_RULES = {"SKY-D409", "SKY-D410", "SKY-D411"}
MAX_CHECKS = 4096
_WORKLOADS = {
    ("v1", "Pod"): ("spec",),
    ("v1", "PodTemplate"): ("template", "spec"),
    ("v1", "ReplicationController"): ("spec", "template", "spec"),
    **{
        ("apps/v1", kind): ("spec", "template", "spec")
        for kind in ("Deployment", "DaemonSet", "ReplicaSet", "StatefulSet")
    },
    ("batch/v1", "Job"): ("spec", "template", "spec"),
    ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
}
_NON_POD = {
    "v1": {
        "ConfigMap",
        "Secret",
        "Service",
        "ServiceAccount",
        "Namespace",
        "Node",
        "Endpoints",
        "PersistentVolume",
        "PersistentVolumeClaim",
        "ResourceQuota",
        "LimitRange",
        "Event",
        "Binding",
        "ComponentStatus",
    },
    "networking.k8s.io/v1": {
        "Ingress",
        "IngressClass",
        "NetworkPolicy",
        "IPAddress",
        "ServiceCIDR",
    },
    "rbac.authorization.k8s.io/v1": {
        "Role",
        "ClusterRole",
        "RoleBinding",
        "ClusterRoleBinding",
    },
    "storage.k8s.io/v1": {
        "StorageClass",
        "VolumeAttachment",
        "CSIDriver",
        "CSINode",
        "CSIStorageCapacity",
    },
    "policy/v1": {"PodDisruptionBudget", "Eviction"},
    "autoscaling/v1": {"HorizontalPodAutoscaler"},
    "autoscaling/v2": {"HorizontalPodAutoscaler"},
    "apiextensions.k8s.io/v1": {"CustomResourceDefinition"},
    "admissionregistration.k8s.io/v1": {
        "ValidatingWebhookConfiguration",
        "MutatingWebhookConfiguration",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
    },
    "coordination.k8s.io/v1": {"Lease"},
    "discovery.k8s.io/v1": {"EndpointSlice"},
    "scheduling.k8s.io/v1": {"PriorityClass"},
    "certificates.k8s.io/v1": {"CertificateSigningRequest"},
}
_CONTAINERS = ("containers", "initContainers", "ephemeralContainers")
_HOST_FLAGS = ("hostPID", "hostIPC", "hostNetwork")
_SENSITIVE_DIRS = ("/etc", "/proc", "/sys", "/var/lib/kubelet")
_SOCKETS = tuple(
    f"{prefix}/{suffix}"
    for prefix in ("/run", "/var/run")
    for suffix in (
        "docker.sock",
        "containerd/containerd.sock",
        "crio/crio.sock",
        "cri-dockerd.sock",
        "dockershim.sock",
        "k3s/containerd/containerd.sock",
        "podman/podman.sock",
    )
)
_NAMES = {
    "SKY-D409": "Privileged Kubernetes container",
    "SKY-D410": "Kubernetes host namespace sharing",
    "SKY-D411": "Sensitive Kubernetes hostPath mount",
}


def _mapping_path(value, path):
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _literal_string(value, max_length=4096):
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= max_length
        and not any(
            marker in value for marker in ("{{", "}}", "${", "$(", "\x00", "\n", "\r")
        )
    )


def _host_path(value):
    if (
        not _literal_string(value)
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or ".." in value.split("/")
    ):
        return None
    return posixpath.normpath(value)


def _contains(parent, child):
    return parent == child or child.startswith(parent.rstrip("/") + "/")


def _sensitivity(path):
    if path == "/":
        return "host_filesystem_root"
    for directory in _SENSITIVE_DIRS:
        if _contains(directory, path) or _contains(path, directory):
            return "host_system_or_credentials"
    for socket in _SOCKETS:
        if _contains(path, socket):
            return "container_runtime_api"
    return None


class _Evaluator:
    def __init__(self, project, ignore):
        self.project = project
        self.ignore = set(ignore or ())
        self.checks = []
        self.findings = []
        self.resources = 0
        self.workloads = 0
        self.unsupported = []
        self.items = 0
        self.exhausted = False

    def check(
        self,
        manifest,
        resource,
        path,
        rule,
        status,
        reason,
        evidence=None,
        message=None,
    ):
        if self.exhausted:
            return
        if len(self.checks) >= MAX_CHECKS:
            self.exhausted = True
            self.project.error(
                manifest.file,
                "kubernetes_budget_exceeded",
                "Kubernetes policy evaluation budget exhausted",
                manifest.line(path),
            )
            for required in sorted(SUPPORTED_RULES):
                self.checks.append(
                    {
                        "rule_id": required,
                        "resource": resource,
                        "resource_type": "kubernetes_workload",
                        "file": str(manifest.file),
                        "line": manifest.line(path),
                        "status": "unknown",
                        "reason": "policy_evaluation_budget",
                        "evidence": {},
                    }
                )
            return
        if rule in self.ignore:
            status, reason = "unknown", "rule_ignored"
        row = {
            "rule_id": rule,
            "resource": resource,
            "resource_type": "kubernetes_workload",
            "file": str(manifest.file),
            "line": manifest.line(path),
            "status": status,
            "reason": reason,
            "evidence": evidence or {},
        }
        self.checks.append(row)
        if status != "unsafe":
            return
        finding = config_finding(
            rule_id=rule,
            domain="deployment",
            provider="kubernetes",
            name=_NAMES[rule],
            message=message or _NAMES[rule],
            file=manifest.file,
            line=row["line"],
            severity="HIGH",
            value=resource,
            finding_type="kubernetes_security",
        )
        finding["metadata"] = {
            "resource": resource,
            "policy_scope": "declaration_policy",
            "review_required": True,
            **row["evidence"],
        }
        host_line = row["evidence"].get("host_path_line")
        if rule == "SKY-D411" and isinstance(host_line, int):
            finding["related_locations"] = [
                {
                    "file": str(manifest.file),
                    "start_line": line,
                    "end_line": line,
                }
                for line in sorted({host_line, *row["evidence"].get("mount_lines", [])})
            ]
        self.findings.append(finding)

    def unknown(self, manifest, resource, path, reason):
        for rule in sorted(SUPPORTED_RULES):
            self.check(manifest, resource, path, rule, "unknown", reason)

    def document(self, manifest, data, prefix=(), depth=0):
        if self.exhausted:
            return
        self.items += 1
        if self.items > 4096 or depth > 8:
            self.unknown(manifest, "List", prefix, "manifest_list_budget")
            return
        if not isinstance(data, dict):
            self.unknown(manifest, "List item", prefix, "invalid_manifest_shape")
            return
        api, kind = data.get("apiVersion"), data.get("kind")
        if "apiVersion" not in data and "kind" not in data:
            if prefix:
                self.unknown(manifest, "List item", prefix, "missing_manifest_identity")
            return  # Ordinary non-Kubernetes YAML.
        if (
            "kind" not in data
            and isinstance(api, str)
            and api not in {"v1", "apps/v1", "batch/v1"}
        ):
            return  # For example, a Helm Chart.yaml apiVersion, not a manifest.
        self.resources += 1
        if not _literal_string(api, 253) or not _literal_string(kind, 63):
            self.unknown(
                manifest, "unresolved_manifest", prefix, "unresolved_manifest_identity"
            )
            return
        metadata = data.get("metadata")
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if (metadata is not None and not isinstance(metadata, dict)) or (
            name is not None and not _literal_string(name, 253)
        ):
            self.unknown(
                manifest,
                f"{kind}/<unresolved-name>",
                prefix + ("metadata",),
                "unresolved_resource_name",
            )
            return
        resource = f"{kind}/{name}" if name is not None else kind
        if (api, kind) == ("v1", "List"):
            items = data.get("items")
            if not isinstance(items, list):
                self.unknown(
                    manifest, resource, prefix + ("items",), "invalid_manifest_list"
                )
                return
            for index, item in enumerate(items[:4096]):
                self.document(manifest, item, prefix + ("items", index), depth + 1)
                if self.items > 4096:
                    break
            if len(items) > 4096:
                self.unknown(
                    manifest, resource, prefix + ("items",), "manifest_list_budget"
                )
            return
        spec_path = _WORKLOADS.get((api, kind))
        if spec_path is None:
            if kind in _NON_POD.get(api, set()):
                for rule in sorted(SUPPORTED_RULES):
                    self.check(
                        manifest,
                        resource,
                        prefix,
                        rule,
                        "not_applicable",
                        "non_workload_resource",
                    )
            else:
                self.unsupported.append(
                    {
                        "resource": resource,
                        "file": str(manifest.file),
                        "line": manifest.line(prefix),
                    }
                )
                self.unknown(
                    manifest, resource, prefix, "unsupported_resource_or_api_version"
                )
            return
        self.workloads += 1
        spec = _mapping_path(data, spec_path)
        path = prefix + spec_path
        if not isinstance(spec, dict):
            self.unknown(manifest, resource, path, "invalid_pod_spec")
            return
        self.namespaces(manifest, resource, path, spec)
        volumes = self.volumes(spec)
        names = Counter(
            container.get("name")
            for group in _CONTAINERS
            for container in (
                spec.get(group) if isinstance(spec.get(group), list) else []
            )
            if isinstance(container, dict) and isinstance(container.get("name"), str)
        )
        for group in _CONTAINERS:
            containers = spec.get(group)
            if containers is None and group != "containers":
                continue
            if not isinstance(containers, list) or (
                not containers and group == "containers"
            ):
                for rule in ("SKY-D409", "SKY-D411"):
                    self.check(
                        manifest,
                        resource,
                        path + (group,),
                        rule,
                        "unknown",
                        "invalid_container_list",
                    )
                continue
            for index, container in enumerate(containers):
                at = path + (group, index)
                if (
                    not isinstance(container, dict)
                    or not _literal_string(container.get("name"), 63)
                    or names[container["name"]] != 1
                ):
                    for rule in ("SKY-D409", "SKY-D411"):
                        self.check(
                            manifest,
                            resource,
                            at,
                            rule,
                            "unknown",
                            "invalid_or_ambiguous_container",
                        )
                    continue
                self.container(manifest, resource, at, container, volumes, group)

    def namespaces(self, manifest, resource, path, spec):
        for flag in _HOST_FLAGS:
            value = spec.get(flag)
            status = (
                "unsafe"
                if value is True
                else "safe"
                if value is None or value is False
                else "unknown"
            )
            self.check(
                manifest,
                resource,
                path + (flag,),
                "SKY-D410",
                status,
                "host_namespace_enabled"
                if value is True
                else "host_namespace_disabled"
                if status == "safe"
                else "non_boolean_host_namespace",
                {
                    "field": flag,
                    "declared_value": value
                    if value is None or isinstance(value, bool)
                    else None,
                },
                f"{resource} sets {flag}: true, sharing a host namespace. Review whether this workload needs host-level access.",
            )

    @staticmethod
    def volumes(spec):
        values = spec.get("volumes")
        if values is None:
            return {}
        if not isinstance(values, list):
            return None
        result = {}
        for index, value in enumerate(values):
            if not isinstance(value, dict) or not _literal_string(
                value.get("name"), 63
            ):
                return None
            name = value["name"]
            result[name] = None if name in result else (value, index)
        return result

    def container(self, manifest, resource, path, container, volumes, group):
        name = container["name"]
        evidence = {"container": name, "container_group": group}
        security = container.get("securityContext")
        if security is None:
            status, reason = "safe", "privileged_not_enabled"
        elif not isinstance(security, dict):
            status, reason = "unknown", "invalid_container_security_context"
        else:
            privileged = security.get("privileged")
            status = (
                "unsafe"
                if privileged is True
                else "safe"
                if privileged is None or privileged is False
                else "unknown"
            )
            reason = (
                "privileged_enabled"
                if status == "unsafe"
                else "privileged_not_enabled"
                if status == "safe"
                else "non_boolean_privileged"
            )
        self.check(
            manifest,
            resource,
            path + ("securityContext", "privileged"),
            "SKY-D409",
            status,
            reason,
            evidence,
            f"Container {name} in {resource} explicitly enables privileged mode. Review its need for elevated host capabilities and reduce access where possible.",
        )
        mounts = container.get("volumeMounts")
        if mounts is None:
            self.check(
                manifest,
                resource,
                path,
                "SKY-D411",
                "safe",
                "no_hostpath_mounts",
                evidence,
            )
        elif not isinstance(mounts, list):
            self.check(
                manifest,
                resource,
                path + ("volumeMounts",),
                "SKY-D411",
                "unknown",
                "invalid_volume_mounts",
                evidence,
            )
        else:
            for index, mount in enumerate(mounts):
                self.mount(
                    manifest,
                    resource,
                    path + ("volumeMounts", index),
                    mount,
                    volumes,
                    evidence,
                )
            if not mounts:
                self.check(
                    manifest,
                    resource,
                    path,
                    "SKY-D411",
                    "safe",
                    "no_hostpath_mounts",
                    evidence,
                )
        devices = container.get("volumeDevices")
        if devices:
            self.check(
                manifest,
                resource,
                path + ("volumeDevices",),
                "SKY-D411",
                "unknown",
                "block_device_mounts_not_evaluated",
                evidence,
            )

    def mount(self, manifest, resource, path, mount, volumes, evidence):
        rule = "SKY-D411"
        if (
            not isinstance(mount, dict)
            or not _literal_string(mount.get("name"), 63)
            or _host_path(mount.get("mountPath")) is None
        ):
            self.check(
                manifest,
                resource,
                path,
                rule,
                "unknown",
                "invalid_volume_mount",
                evidence,
            )
            return
        if volumes is None or not isinstance(volumes.get(mount["name"]), tuple):
            self.check(
                manifest,
                resource,
                path,
                rule,
                "unknown",
                "unresolved_or_ambiguous_volume",
                evidence,
            )
            return
        volume, volume_index = volumes[mount["name"]]
        if "hostPath" not in volume:
            self.check(
                manifest, resource, path, rule, "safe", "non_hostpath_volume", evidence
            )
            return
        host = volume["hostPath"]
        host_path = _host_path(host.get("path")) if isinstance(host, dict) else None
        sub_path = mount.get("subPath")
        effective = host_path
        if sub_path not in (None, ""):
            if (
                not _literal_string(sub_path)
                or sub_path.startswith("/")
                or "\\" in sub_path
                or ".." in sub_path.split("/")
            ):
                effective = None
            elif effective is not None:
                effective = _host_path(posixpath.join(effective, sub_path))
        if mount.get("subPathExpr") not in (None, ""):
            effective = None
        read_only = mount.get("readOnly")
        if read_only is not None and not isinstance(read_only, bool):
            effective = None
        evidence = {
            **evidence,
            "volume": mount["name"],
            "host_path": host.get("path")
            if isinstance(host, dict) and _literal_string(host.get("path"))
            else None,
            "host_path_line": manifest.line(
                path[:-4] + ("volumes", volume_index, "hostPath", "path")
            ),
            "mount_path": mount["mountPath"],
            "mount_lines": [
                manifest.line(path + (key,))
                for key in ("name", "mountPath", "subPath", "subPathExpr", "readOnly")
                if key in mount
            ],
            "effective_host_path": effective,
            "read_only": read_only
            if isinstance(read_only, bool)
            else False
            if read_only is None
            else None,
        }
        if effective is None:
            self.check(
                manifest,
                resource,
                path,
                rule,
                "unknown",
                "unresolved_hostpath_mount",
                evidence,
            )
            return
        reason = _sensitivity(effective)
        if reason is None:
            self.check(
                manifest,
                resource,
                path,
                rule,
                "safe",
                "outside_sensitive_hostpath_policy",
                evidence,
            )
            return
        access = "read-only" if read_only else "writable"
        caveat = (
            " Read-only access can still expose host credentials or runtime APIs; it is not a general security boundary."
            if read_only
            else ""
        )
        self.check(
            manifest,
            resource,
            path,
            rule,
            "unsafe",
            reason,
            evidence,
            f"Container {evidence['container']} in {resource} mounts sensitive host path {effective} ({access}). Review the host access and replace it with a narrower volume where possible.{caveat}",
        )


def scan_kubernetes(
    root,
    *,
    changed_files=None,
    ignore=None,
    analysis_errors=None,
    configuration_coverage=None,
    exclude_folders=None,
    scan_paths=None,
    required_rules=None,
):
    project = load_project(
        root,
        changed_files=changed_files,
        scan_paths=scan_paths,
        exclude_folders=exclude_folders,
    )
    evaluator = _Evaluator(project, ignore)
    for manifest in project.manifests:
        evaluator.document(manifest, manifest.data)
    counts = Counter(check["status"] for check in evaluator.checks)
    errors = list(project.analysis_errors)
    requested = (
        [required_rules] if isinstance(required_rules, str) else required_rules or ()
    )
    required = {str(rule).upper() for rule in requested} & SUPPORTED_RULES
    for rule in sorted(required):
        unknown = [
            check
            for check in evaluator.checks
            if check["rule_id"] == rule and check["status"] == "unknown"
        ]
        if (
            unknown
            or project.coverage["status"] == "incomplete"
            or rule in set(ignore or ())
        ):
            at = (
                unknown[0]
                if unknown
                else errors[0]
                if errors
                else (project.coverage["discovery_errors"] or [{}])[0]
            )
            errors.append(
                {
                    "rule_id": "SKY-ANALYSIS-INCOMPLETE",
                    "severity": "HIGH",
                    "kind": "kubernetes_evaluation_incomplete",
                    "error_type": "KubernetesPolicyUnresolved",
                    "file": at.get("file", str(Path(root))),
                    "line": at.get("line", 1),
                    "column": 1,
                    "message": f"Required Kubernetes policy {rule} could not be fully evaluated",
                    "required_rule": rule,
                }
            )
    partial = bool(
        errors or counts["unknown"] or project.coverage["status"] == "incomplete"
    )
    evaluation_status = (
        "partial"
        if partial
        else "complete"
        if evaluator.workloads
        else "not_applicable"
    )
    coverage = {
        **project.coverage,
        "status": "incomplete" if partial else "complete",
        "evaluation_status": evaluation_status,
        "supported_rules": sorted(SUPPORTED_RULES),
        "checks": evaluator.checks,
        "checks_evaluated": len(evaluator.checks),
        "evaluation_counts": {
            status: counts[status]
            for status in ("unsafe", "safe", "unknown", "not_applicable")
        },
        "resources": evaluator.resources,
        "workloads": evaluator.workloads,
        "unsupported_resource_count": len(evaluator.unsupported),
        "unsupported_resources": evaluator.unsupported,
        "policy_scope": "declaration_policy",
        "limits": {
            "rendering": "not_performed",
            "custom_resources": "not_evaluated",
            "hostpath_platform": "literal_posix_paths",
            "runtime_state": "not_observed",
            "yaml_aliases_and_merges": "not_evaluated",
        },
    }
    if analysis_errors is not None:
        analysis_errors.extend(errors)
    if configuration_coverage is not None:
        configuration_coverage["kubernetes"] = coverage
    return evaluator.findings
