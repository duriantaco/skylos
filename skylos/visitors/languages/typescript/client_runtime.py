from __future__ import annotations

import os
import re
from functools import lru_cache

from .resolve import _read_json_file

_DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "peerDependencies")
_DEVICE_RUNTIMES = frozenset({"react-native", "expo"})
_BROWSER_RUNTIMES = frozenset(
    {"vue", "react-dom", "svelte", "preact", "@angular/core", "solid-js"}
)
_SERVER_RUNTIMES = frozenset(
    {
        "express",
        "fastify",
        "koa",
        "hono",
        "next",
        "nuxt",
        "astro",
        "restify",
        "electron",
        "vike",
        "@nestjs/core",
        "@hapi/hapi",
        "@sveltejs/kit",
        "@remix-run/node",
        "@remix-run/server-runtime",
        "@angular/ssr",
        "@solidjs/start",
        "@tanstack/react-start",
    }
)
_NODE_MODULE_RE = re.compile(
    rb"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]"""
    rb"""(?:node:[^'"]+|fs|fs/promises|http|https|http2|net|tls|dgram|cluster"""
    rb"""|child_process|worker_threads)['"]"""
)


@lru_cache(maxsize=4096)
def _client_only_package(directory: str) -> bool:
    while True:
        manifest = os.path.join(directory, "package.json")
        if os.path.isfile(manifest):
            break
        parent = os.path.dirname(directory)
        if parent == directory:
            return False
        directory = parent
    data = _read_json_file(manifest)
    names = set()
    for field in _DEPENDENCY_FIELDS:
        if isinstance(data.get(field), dict):
            names.update(data[field])
    if names & _SERVER_RUNTIMES:
        return False
    return bool(names & (_DEVICE_RUNTIMES | _BROWSER_RUNTIMES))


def _has_client_directive(root_node, source_bytes: bytes) -> bool:
    for child in root_node.children:
        if child.type == "comment":
            continue
        if child.type != "expression_statement" or not child.named_children:
            return False
        literal = child.named_children[0]
        if literal.type != "string":
            return False
        text = source_bytes[literal.start_byte : literal.end_byte].decode(
            "utf-8", "replace"
        )
        return text[1:-1] == "use client"
    return False


def runs_only_on_client(root_node, source_bytes: bytes, file_path: str) -> bool:
    if _has_client_directive(root_node, source_bytes):
        return True
    if _NODE_MODULE_RE.search(source_bytes):
        return False
    directory = os.path.dirname(os.path.abspath(os.fspath(file_path)))
    return _client_only_package(directory)
