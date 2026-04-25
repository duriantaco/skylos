from importlib import import_module


PLUGIN_MODULE = "plugins.email"


def load_plugin(name=PLUGIN_MODULE):
    module = import_module(name)
    return module.send_email


def run_notification():
    sender = load_plugin()
    return sender("ops@example.com")


def unused_loader():
    return "stale"


RESULT = run_notification()
