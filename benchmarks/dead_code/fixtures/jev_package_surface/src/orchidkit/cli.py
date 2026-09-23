"""Installed command entry point for profile-driven processing."""

import argparse
import importlib
import json
from importlib import resources


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="orchid")
    parser.add_argument("value")
    parser.add_argument("--profile", default=None)
    return parser.parse_args(argv)


def read_profiles():
    path = resources.files("orchidkit").joinpath("config", "pipelines.json")
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_handler(reference):
    module_name, symbol = reference.split(":", 1)
    module = importlib.import_module(module_name)
    return getattr(module, symbol)


def main(argv=None):
    args = parse_args(argv)
    config = read_profiles()
    profile = args.profile or config["default"]
    handler = resolve_handler(config["profiles"][profile])
    return handler(args.value)
