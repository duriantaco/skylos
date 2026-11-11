"""Bounded review policies for literal Kubernetes workload manifests."""

from skylos.rules.config.kubernetes.scanner import scan_kubernetes

__all__ = ["scan_kubernetes"]
