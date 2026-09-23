import importlib
import json
from pathlib import Path

from .registry import PLUGIN_REGISTRY


def _invoke(target, context):
    module_name, symbol = target.rsplit(".", 1)
    module = importlib.import_module(module_name)
    return getattr(module, symbol)(context)


def run_workflows():
    config_path = Path(__file__).resolve().parents[1] / "config" / "workflows.json"
    configuration = json.loads(config_path.read_text(encoding="utf-8"))
    context = {"trace": []}
    for workflow in configuration["workflows"]:
        for callback in workflow["before"]:
            _invoke(callback, context)
        for action in workflow["steps"]:
            _invoke(action, context)
        for plugin_key in workflow["plugins"]:
            _invoke(PLUGIN_REGISTRY[plugin_key], context)
        for callback in workflow["after"]:
            _invoke(callback, context)
    return context["trace"]


if __name__ == "__main__":
    print(run_workflows())
