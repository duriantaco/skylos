from __future__ import annotations

CWE_MAP: dict[str, list[dict[str, str]]] = {
    # Logic rules
    "SKY-L001": [
        {
            "id": "CWE-1321",
            "name": "Improperly Controlled Modification of Object Prototype Attributes",
        }
    ],
    "SKY-L002": [
        {"id": "CWE-396", "name": "Declaration of Catch for Generic Exception"}
    ],
    "SKY-L003": [
        {"id": "CWE-597", "name": "Use of Wrong Operator in String Comparison"}
    ],
    "SKY-L004": [{"id": "CWE-705", "name": "Incorrect Control Flow Scoping"}],
    "SKY-L005": [{"id": "CWE-563", "name": "Assignment to Variable without Use"}],
    "SKY-L006": [{"id": "CWE-394", "name": "Unexpected Status Code or Return Value"}],
    "SKY-L007": [{"id": "CWE-391", "name": "Unchecked Error Condition"}],
    "SKY-L008": [
        {
            "id": "CWE-772",
            "name": "Missing Release of Resource after Effective Lifetime",
        }
    ],
    "SKY-L009": [{"id": "CWE-489", "name": "Active Debug Code"}],
    "SKY-L010": [{"id": "CWE-546", "name": "Suspicious Comment"}],
    "SKY-L011": [
        {"id": "CWE-295", "name": "Improper Certificate Validation"},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery"},
    ],
    "SKY-L012": [{"id": "CWE-476", "name": "NULL Pointer Dereference"}],
    "SKY-L013": [{"id": "CWE-330", "name": "Use of Insufficiently Random Values"}],
    "SKY-L014": [{"id": "CWE-798", "name": "Use of Hard-coded Credentials"}],
    "SKY-L016": [
        {
            "id": "CWE-1188",
            "name": "Initialization with Hard-Coded Network Resource Configuration",
        }
    ],
    "SKY-L017": [
        {
            "id": "CWE-209",
            "name": "Generation of Error Message Containing Sensitive Information",
        }
    ],
    "SKY-L020": [
        {
            "id": "CWE-732",
            "name": "Incorrect Permission Assignment for Critical Resource",
        }
    ],
    "SKY-L023": [{"id": "CWE-476", "name": "NULL Pointer Dereference"}],
    "SKY-L024": [
        {"id": "CWE-1127", "name": "Compilation with Insufficient Warnings or Errors"}
    ],
    "SKY-L026": [{"id": "CWE-1164", "name": "Irrelevant Code"}],
    "SKY-L027": [
        {"id": "CWE-1095", "name": "Loop Condition Value Update within the Loop"}
    ],  # maintainability: duplicated literals
    "SKY-L028": [
        {
            "id": "CWE-1075",
            "name": "Unconditional Control Flow Transfer in Finally Block",
        }
    ],  # complex control flow
    "SKY-L029": [
        {
            "id": "CWE-1064",
            "name": "Invokable Control Element with Signature Containing an Excessive Number of Parameters",
        }
    ],
    # Complexity / structure
    "SKY-Q301": [{"id": "CWE-1121", "name": "Excessive McCabe Cyclomatic Complexity"}],
    "SKY-Q302": [{"id": "CWE-1124", "name": "Excessively Deep Nesting"}],
    "SKY-Q306": [{"id": "CWE-1121", "name": "Excessive McCabe Cyclomatic Complexity"}],
    "SKY-L021": [
        {"id": "CWE-693", "name": "Protection Mechanism Failure"},
        {"id": "CWE-862", "name": "Missing Authorization"},
    ],
    "SKY-Q401": [{"id": "CWE-667", "name": "Improper Locking"}],
    "SKY-Q501": [{"id": "CWE-1093", "name": "Excessively Complex Data Representation"}],
    "SKY-Q701": [{"id": "CWE-1047", "name": "Modules with Circular Dependencies"}],
    "SKY-Q702": [{"id": "CWE-1093", "name": "Excessively Complex Data Representation"}],
    "SKY-C303": [
        {
            "id": "CWE-1064",
            "name": "Invokable Control Element with Signature Containing an Excessive Number of Parameters",
        }
    ],
    "SKY-C304": [
        {
            "id": "CWE-1080",
            "name": "Source Code File with Excessive Number of Lines of Code",
        }
    ],
    # Performance
    "SKY-P401": [{"id": "CWE-400", "name": "Uncontrolled Resource Consumption"}],
    "SKY-P402": [{"id": "CWE-400", "name": "Uncontrolled Resource Consumption"}],
    "SKY-P403": [{"id": "CWE-407", "name": "Inefficient Algorithmic Complexity"}],
    # Unreachable
    "SKY-UC001": [{"id": "CWE-561", "name": "Dead Code"}],
}

STANDARD_REFS: dict[str, list[str]] = {
    "SKY-Q301": ["ISO/IEC 5055:2021 §6.3.4", "McCabe Cyclomatic Complexity"],
    "SKY-Q306": ["SonarQube S3776", "Cognitive Complexity"],
    "SKY-Q302": ["ISO/IEC 5055:2021 §6.3.5"],
    "SKY-Q501": ["CK Metrics: WMC (Weighted Methods per Class)"],
    "SKY-Q701": ["CK Metrics: CBO (Coupling Between Objects)", "ISO/IEC 9126"],
    "SKY-Q702": ["CK Metrics: LCOM (Lack of Cohesion of Methods)", "ISO/IEC 9126"],
    "SKY-C303": ["ISO/IEC 5055:2021 §6.3.2"],
    "SKY-C304": ["ISO/IEC 5055:2021 §6.3.3"],
}


def enrich_finding(finding: dict) -> dict:
    rule_id = finding.get("rule_id", "")
    finding["cwe"] = CWE_MAP.get(rule_id, [])
    finding["standard_refs"] = STANDARD_REFS.get(rule_id, [])
    return finding


def get_cwe_taxa() -> list[dict]:
    """Return unique CWE entries formatted for SARIF taxonomies."""
    seen: set[str] = set()
    taxa: list[dict] = []
    for entries in CWE_MAP.values():
        for entry in entries:
            if entry["id"] not in seen:
                seen.add(entry["id"])
                taxa.append(
                    {
                        "id": entry["id"],
                        "name": entry["name"],
                        "shortDescription": {"text": entry["name"]},
                    }
                )
    return taxa
