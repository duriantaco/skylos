from services.hooks import run_dynamic_hook, run_mutable_runner, run_registered_hook


def dispatch_job(event):
    job = event.get("job", "dynamic")
    if job == "registered":
        return run_registered_hook(event.get("name", "status"))
    if job == "mutable":
        return run_mutable_runner(event)
    return run_dynamic_hook(event.get("hook", "status"), event.get("repo", "."))
