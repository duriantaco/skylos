from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandRisk:
    rule_id: str
    severity: str
    message: str


DATA_EXFIL_RULE = CommandRisk(
    "SKY-D327",
    "CRITICAL",
    (
        "Shell command may exfiltrate environment variables or local secrets "
        "to an external destination."
    ),
)
REMOTE_SCRIPT_RULE = CommandRisk(
    "SKY-D328",
    "HIGH",
    "Remote script is piped into a shell or interpreter. Download and inspect it before execution.",
)
DESTRUCTIVE_RULE = CommandRisk(
    "SKY-D329",
    "HIGH",
    "Broad destructive shell command can remove source, credentials, or user files.",
)
PACKAGE_REGISTRY_RULE = CommandRisk(
    "SKY-D337",
    "HIGH",
    (
        "Command changes or trusts a package registry/index. Verify the "
        "registry owner before installing."
    ),
)
SCOPE_VIOLATION_RULE = CommandRisk(
    "SKY-D338",
    "CRITICAL",
    "Command reads sensitive host credentials or exposes a broad host filesystem scope.",
)
PERSISTENT_MUTATION_RULE = CommandRisk(
    "SKY-D339",
    "HIGH",
    "Command mutates persistent user, shell, scheduler, or package-manager configuration.",
)
PUBLISH_RULE = CommandRisk(
    "SKY-D340",
    "HIGH",
    "Command publishes or pushes a package/artifact. Require explicit release intent.",
)
UNTRUSTED_TOOL_RULE = CommandRisk(
    "SKY-D341",
    "HIGH",
    "Command auto-installs or runs package-managed code. Pin and review the tool first.",
)
