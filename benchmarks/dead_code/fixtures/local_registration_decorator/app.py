ACTIONS = {}
STARTUP_CALLBACKS = []


def action(name):
    def decorator(func):
        ACTIONS[name] = func
        return func

    return decorator


def on_startup(func):
    STARTUP_CALLBACKS.append(func)
    return func


@action("resize")
def resize_image(payload):
    return payload["image"]


@action("archive")
def archive_image(payload):
    return payload["archive_id"]


@on_startup
def warm_cache():
    return "ready"


def dispatch(name, payload):
    return ACTIONS[name](payload)


def unused_action(payload):
    return payload.get("stale")
