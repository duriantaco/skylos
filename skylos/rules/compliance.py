COMPLIANCE_MAPPINGS = {
    "SKY-D201": [
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Injection Flaws"},
        {"framework": "PCI_DSS_4", "requirement": "6.5.1", "title": "Injection Flaws"},
        {"framework": "OWASP_TOP10", "requirement": "A03:2021", "title": "Injection"},
        {"framework": "SOC2", "requirement": "CC6.1", "title": "Security Controls"},
        {
            "framework": "HIPAA",
            "requirement": "164.312(a)(1)",
            "title": "Access Control",
        },
    ],
    "SKY-D217": [
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Injection Flaws"},
        {"framework": "OWASP_TOP10", "requirement": "A03:2021", "title": "Injection"},
    ],
    "SKY-D212": [
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Injection Flaws"},
        {"framework": "OWASP_TOP10", "requirement": "A03:2021", "title": "Injection"},
        {"framework": "SOC2", "requirement": "CC6.1", "title": "Security Controls"},
    ],
    "SKY-D216": [
        {"framework": "OWASP_TOP10", "requirement": "A10:2021", "title": "SSRF"},
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Security Flaws"},
    ],
    "SKY-D214": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A01:2021",
            "title": "Broken Access Control",
        },
        {
            "framework": "PCI_DSS_4",
            "requirement": "6.5.8",
            "title": "Improper Access Control",
        },
    ],
    "SKY-S101": [
        {
            "framework": "PCI_DSS_4",
            "requirement": "3.5.1",
            "title": "Protect Stored Credentials",
        },
        {
            "framework": "PCI_DSS_4",
            "requirement": "8.3.1",
            "title": "Authentication Management",
        },
        {"framework": "SOC2", "requirement": "CC6.1", "title": "Security Controls"},
        {"framework": "SOC2", "requirement": "CC6.7", "title": "Data Classification"},
        {
            "framework": "HIPAA",
            "requirement": "164.312(a)(1)",
            "title": "Access Control",
        },
        {
            "framework": "ISO_27001",
            "requirement": "A.9.4.3",
            "title": "Password Management",
        },
    ],
    "SKY-D101": [
        {"framework": "OWASP_TOP10", "requirement": "A03:2021", "title": "Injection"},
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Code Injection"},
    ],
    "SKY-D102": [
        {"framework": "OWASP_TOP10", "requirement": "A03:2021", "title": "Injection"},
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Code Injection"},
    ],
    "SKY-D502": [
        {"framework": "OWASP_TOP10", "requirement": "A03:2021", "title": "Injection"},
        {
            "framework": "PCI_DSS_4",
            "requirement": "6.5.7",
            "title": "Cross-Site Scripting",
        },
    ],
    "SKY-D103": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A08:2021",
            "title": "Insecure Deserialization",
        },
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Security Flaws"},
    ],
    "SKY-D230": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A01:2021",
            "title": "Broken Access Control",
        },
    ],
    "SKY-D231": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A05:2021",
            "title": "Security Misconfiguration",
        },
    ],
    "SKY-D232": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A02:2021",
            "title": "Cryptographic Failures",
        },
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Security Flaws"},
    ],
    "SKY-D233": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A08:2021",
            "title": "Insecure Deserialization",
        },
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Security Flaws"},
    ],
    "SKY-D234": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A01:2021",
            "title": "Broken Access Control",
        },
    ],
    "SKY-D240": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A03:2021",
            "title": "Injection",
        },
        {"framework": "PCI_DSS_4", "requirement": "6.2.4", "title": "Security Flaws"},
    ],
    "SKY-D241": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A07:2021",
            "title": "Identification and Authentication Failures",
        },
        {"framework": "PCI_DSS_4", "requirement": "6.5.10", "title": "Authentication"},
    ],
    "SKY-D242": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A01:2021",
            "title": "Broken Access Control",
        },
    ],
    "SKY-D243": [
        {
            "framework": "OWASP_TOP10",
            "requirement": "A05:2021",
            "title": "Security Misconfiguration",
        },
        {"framework": "PCI_DSS_4", "requirement": "1.3.1", "title": "Network Controls"},
    ],
    "SKY-D244": [
        {
            "framework": "PCI_DSS_4",
            "requirement": "3.5.1",
            "title": "Protect Stored Credentials",
        },
        {"framework": "SOC2", "requirement": "CC6.1", "title": "Security Controls"},
    ],
}

FRAMEWORK_NAMES = {
    "PCI_DSS_4": "PCI DSS 4.0",
    "OWASP_TOP10": "OWASP Top 10",
    "SOC2": "SOC 2",
    "HIPAA": "HIPAA",
    "ISO_27001": "ISO 27001",
    "GDPR": "GDPR",
    "NIST_CSF": "NIST CSF",
}


def get_compliance_tags(rule_id):
    return COMPLIANCE_MAPPINGS.get(rule_id, [])


def enrich_finding_with_compliance(finding):
    rule_id = finding.get("rule_id", "")
    tags = get_compliance_tags(rule_id)

    if tags:
        finding["compliance_tags"] = tags
        displays = []
        for tag in tags:
            fw = FRAMEWORK_NAMES.get(tag["framework"], tag["framework"])
            displays.append(f"{fw} {tag['requirement']}")
        finding["compliance_display"] = displays

    return finding


def enrich_findings_with_compliance(findings):
    for finding in findings:
        enrich_finding_with_compliance(finding)
    return findings
