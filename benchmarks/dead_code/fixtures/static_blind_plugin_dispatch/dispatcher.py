import importlib

from registry import HANDLER_PATHS


def dispatch_event(event):
    handler_path = HANDLER_PATHS[event.get("type", "pay")]
    module_name, func_name = handler_path.split(":")
    handler = getattr(importlib.import_module(module_name), func_name)
    return handler(event.get("payload", {}))
