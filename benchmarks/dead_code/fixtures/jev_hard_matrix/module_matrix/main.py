from importlib import import_module

from plan import STEPS


def render():
    result = []
    for module_name, variant in STEPS:
        module = import_module("workers." + module_name)
        result.append(getattr(module, "render_" + variant)())
    return result


if __name__ == "__main__":
    print(render())
