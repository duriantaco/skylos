import subprocess


ALLOWED = {
    "status": ["git", "status", "--short"],
    "fetch": ["git", "fetch", "origin"],
}


def run_named_hook(name, repo_path):
    cmd = f"cd {repo_path} && {name}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def run_builtin(name):
    return subprocess.run(ALLOWED[name], check=False, capture_output=True, text=True)
