from pathlib import Path

from rich.console import Console


def run_init_command() -> int:
    console = Console()
    path = Path("pyproject.toml")

    template = """
[tool.skylos]
complexity = 10
nesting = 3
max_args = 5
max_lines = 50
god_file_max_lines = 500
god_file_max_definitions = 40
god_file_max_top_level_definitions = 25
duplicate_strings = 3
model = "gpt-4.1"
exclude = []
ignore = []

[tool.skylos.masking]
names = []
decorators = []
bases = []

[tool.skylos.dead_code]
entrypoints = []

# [[tool.skylos.dead_code.entrypoints]]
# type = "class"
# name = "Main"
# path = "**/main.py"
# base_classes = ["Application"]
# reason = "framework entrypoint"
#
# [[tool.skylos.dead_code.entrypoints]]
# type = "method"
# name = ["create", "pre_hook", "post_hook"]
# parent = { name = "Main", base_classes = ["Application"] }
# reason = "framework lifecycle method"

[tool.skylos.templates]
# security = ".skylos/templates/security.md"
# quality = ".skylos/templates/quality.md"
# security_audit = ".skylos/templates/security_audit.md"
# review = ".skylos/templates/review.md"

[tool.skylos.vibe]
extra_phantom_names = []
extra_phantom_decorators = []
extra_credential_names = []
extra_sensitive_file_keywords = []
extra_network_timeout_calls = []

[tool.skylos.architecture]
strict = false
# Q802/Q803 are file-level I/A/D architecture signals by default. Set this to
# true only if those signals should block strict gates in this project.
enforce_iad = false

# [[tool.skylos.architecture.layers]]
# name = "api"
# patterns = ["app.api", "app.routes"]
#
# [[tool.skylos.architecture.layers]]
# name = "domain"
# patterns = ["app.domain", "app.models"]
#
# [[tool.skylos.architecture.rules]]
# from = "domain"
# deny = ["api"]

[tool.skylos.whitelist]
names = []

[tool.skylos.whitelist.documented]

[tool.skylos.whitelist.temporary]

[tool.skylos.gate]
fail_on_critical = true
max_critical = 0 
max_high = 5
max_security = 0
max_quality = 10
strict = false
"""

    if path.exists():
        content = path.read_text(encoding="utf-8")
        if "[tool.skylos" in content:
            import re

            content = re.sub(r"\[tool\.skylos[^\]]*\](?:\n(?!\[).*)*\n*", "", content)
            content = content.rstrip() + "\n"
            path.write_text(content, encoding="utf-8")
            console.print("[brand]Resetting Skylos configuration...[/brand]")

        with open(path, "a", encoding="utf-8") as f:
            f.write("\n" + template.strip() + "\n")
    else:
        path.write_text(template.strip(), encoding="utf-8")

    console.print("[good]✓ Configuration initialized![/good]")
    return 0
