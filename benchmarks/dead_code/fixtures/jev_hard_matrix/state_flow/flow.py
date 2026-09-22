from importlib import import_module


START = "amber"
NEXT = {
    "amber": "cobalt",
    "birch": "drift",
    "cobalt": "ember",
    "drift": "fjord",
    "ember": "glade",
    "fjord": "harbor",
    "glade": "iris",
    "harbor": "juniper",
    "iris": "kelp",
    "juniper": "lilac",
    "kelp": "moss",
    "lilac": "nectar",
    "moss": None,
    "nectar": None,
}


def traverse():
    stages = import_module("stages")
    state = START
    output = []
    while state is not None:
        output.append(getattr(stages, "stage_" + state)())
        state = NEXT[state]
    return output
