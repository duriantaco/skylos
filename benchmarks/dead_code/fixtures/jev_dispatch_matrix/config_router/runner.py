import importlib
import json
from pathlib import Path


def run_commands():
    configuration = json.loads(Path(__file__).with_name("routes.json").read_text())
    module = importlib.import_module("actions")
    return [getattr(module, name)() for name in configuration["commands"]]


if __name__ == "__main__":
    print(run_commands())
