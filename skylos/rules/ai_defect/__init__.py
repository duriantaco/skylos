from skylos.rules.ai_defect.phantom_call import PhantomCallRule
from skylos.rules.ai_defect.phantom_decorator import PhantomDecoratorRule
from skylos.rules.ai_defect.dependency_hallucination import (
    scan_python_dependency_hallucinations,
)
from skylos.rules.ai_defect.api_signature_hallucination import (
    scan_python_api_signature_hallucinations,
)
from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    scan_manifest_dependency_hallucinations,
)
from skylos.rules.ai_defect.phantom_refs import scan_repo_phantom_security_references
from skylos.rules.ai_defect.assertion_weakening import detect_assertion_weakening

__all__ = [
    "PhantomCallRule",
    "PhantomDecoratorRule",
    "scan_python_dependency_hallucinations",
    "scan_python_api_signature_hallucinations",
    "scan_manifest_dependency_hallucinations",
    "scan_repo_phantom_security_references",
    "detect_assertion_weakening",
]
