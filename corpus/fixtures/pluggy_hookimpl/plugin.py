import pluggy

hookimpl = pluggy.HookimplMarker("demo")


@hookimpl
def my_hook(config):
    return config


def render_report(config):
    return config
