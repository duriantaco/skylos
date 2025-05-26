from .submodule_a import exported_function as package_function
from .submodule_b import ExportedClass

PACKAGE_CONSTANT = "Package constant"

def package_level_function():
    """Function defined at the package level."""
    return "Package function result"

def unused_package_function():
    """Function defined at package level but never used."""
    return "Unused package function"

__version__ = "1.0.11"