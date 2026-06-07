from __future__ import annotations

import json
from typing import Annotated, Any
from typing_extensions import deprecated


def build_path(
    value: Annotated[Any | None, deprecated("use route_examples")] = None,
    deprecated: bool = False,
):
    if deprecated:
        return "legacy"
    return value


RESULT = build_path("demo")


def unused_builder():
    return "stale"
