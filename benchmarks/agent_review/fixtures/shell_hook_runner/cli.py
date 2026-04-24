from hooks import run_builtin, run_named_hook


def sync_repository(repo_path):
    return run_builtin("fetch")


def execute_custom_hook(name, repo_path):
    return run_named_hook(name, repo_path)
