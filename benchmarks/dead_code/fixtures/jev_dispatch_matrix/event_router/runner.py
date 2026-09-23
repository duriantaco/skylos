import importlib


def replay():
    module = importlib.import_module("receiver")
    events = ("alpha", "gamma", "epsilon", "eta", "iota")
    return [getattr(module, "on_" + event)() for event in events]


if __name__ == "__main__":
    print(replay())
