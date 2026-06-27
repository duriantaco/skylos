import sys as _sys

from skylos.rules.ai_defect import dependency_hallucination as _module

globals().update(_module.__dict__)
_sys.modules[__name__] = _module
