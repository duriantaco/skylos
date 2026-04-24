REGISTRY = {}


def register(name):
    def decorator(func):
        REGISTRY[name] = func
        return func

    return decorator


@register("create")
def handle_create(payload):
    return {"created": payload}


@register("update")
def handle_update(payload):
    return {"updated": payload}


def dispatch(name, payload):
    return REGISTRY[name](payload)


def unused_handler(payload):
    return {"unused": payload}
