import subprocess


def run_safe_builtin(payload):
    COMMANDS = {
        "status": ["git", "status", "--short"],
        "version": ["git", "--version"],
    }
    return subprocess.run(COMMANDS[payload.get("name", "status")], check=False)


def run_mutable_registered(payload):
    COMMANDS = {"status": ["git", "status", "--short"]}
    key = payload.get("name", "custom")
    COMMANDS[key] = [payload.get("tool", "git"), payload.get("arg", "--version")]
    return subprocess.run(COMMANDS[key], check=False)
