__version__ = "2.2.4"

def analyze(*args, **kwargs):
    from .analyzer import analyze as _analyze
    return _analyze(*args, **kwargs)

def debug_test():
    return "debug-ok"

__all__ = ["analyze", "debug_test", "__version__"]
