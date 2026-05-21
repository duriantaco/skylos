import subprocess


def run_dynamic_hook(hook_name, repo_path):
    command = f"cd {repo_path} && ./hooks/{hook_name}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def run_registered_hook(name):
    SAFE_LOCAL = {
        "status": ["git", "status", "--short"],
        "version": ["git", "--version"],
    }
    return subprocess.run(SAFE_LOCAL[name], check=False, capture_output=True, text=True)


def run_mutable_runner(event):
    RUNNERS = {"status": ["git", "status", "--short"]}
    selected = event.get("name", "custom")
    RUNNERS[selected] = [event.get("tool", "git"), event.get("arg", "--version")]
    return subprocess.run(RUNNERS[selected], check=False, capture_output=True, text=True)


def run_sample(template, repo_path):
    command = f"cd {repo_path} && {template}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)
