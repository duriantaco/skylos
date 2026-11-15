import importlib
import sys

ALIASES = {"b": "tool.commands.build"}


def main():
    name = sys.argv[1]
    return importlib.import_module(ALIASES.get(name, name))
