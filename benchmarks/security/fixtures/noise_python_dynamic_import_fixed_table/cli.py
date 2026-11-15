import importlib
import sys

COMMANDS = {"build": "tool.commands.build", "serve": "tool.commands.serve"}


def main():
    if len(sys.argv) > 1 and sys.argv[1] in COMMANDS:
        module = importlib.import_module(COMMANDS[sys.argv[1]])
        return module.main(sys.argv[2:])
    return 1
