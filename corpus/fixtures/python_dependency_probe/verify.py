import importlib.util


def check_dependencies():
    modules = ["backend_engine"]
    for module in modules:
        if importlib.util.find_spec(module):
            print("available")


check_dependencies()
