"""One-line fixes and documentation links for findings.

A fix is chosen for the finding's language: a shell finding never gets
Python advice. Rules without a written fix fall back to the advice clause the
detector put in the message, then to a language-neutral pointer to the docs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePath

from skylos.rules.docs_anchors import RULE_DOCS_ANCHORS

DOCS_PAGE = "https://docs.skylos.dev/rules-reference"

_SUFFIX_LANGUAGES = {
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mts": "js",
    ".cts": "js",
    ".vue": "js",
    ".svelte": "js",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".go": "go",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".php": "php",
    ".rs": "rust",
    ".dart": "dart",
    ".cs": "csharp",
    ".sol": "solidity",
    ".yml": "yaml",
    ".yaml": "yaml",
}
_LANGUAGE_NAMES = {
    "python": "python",
    "javascript": "js",
    "typescript": "js",
    "js": "js",
    "shell": "shell",
    "bash": "shell",
    "sh": "shell",
    "go": "go",
    "java": "java",
    "kotlin": "java",
    "php": "php",
    "rust": "rust",
    "dart": "dart",
    "csharp": "csharp",
    "c#": "csharp",
    "yaml": "yaml",
}
_COMMENT_PREFIX = {
    "python": "#",
    "shell": "#",
    "yaml": "#",
    "js": "//",
    "go": "//",
    "java": "//",
    "php": "//",
    "rust": "//",
    "dart": "//",
    "csharp": "//",
    "solidity": "//",
}

_UNTRUSTED_COMMAND = {
    "default": "Run a fixed command and pass untrusted values only as separate, allowlisted arguments.",
    "python": "Use subprocess.run([...]) with an argument list and shell=False; allowlist any user-controlled value.",
    "js": "Use execFile/spawn with an argument array instead of exec; allowlist any user-controlled value.",
    "shell": 'Quote every expansion ("$var"), allowlist the input, and never pass it to eval, source or sh -c.',
    "go": 'Call exec.Command with the program and each argument separately, never "sh -c"; allowlist input.',
    "java": "Use ProcessBuilder with a fixed program and a separate argument list; allowlist input.",
    "rust": "Use Command::new with a fixed program and .arg() per value, never a shell; allowlist input.",
    "php": "Avoid shell_exec/system with input; use escapeshellarg on each argument or a fixed command.",
    "dart": "Use Process.run with a fixed executable and an argument list, runInShell: false; allowlist input.",
    "csharp": "Start a fixed executable with ArgumentList entries, UseShellExecute = false; allowlist input.",
}
_PATH_TRAVERSAL = {
    "default": "Resolve the path, check it stays inside the allowed base directory, and reject anything else.",
    "python": "Resolve with Path(base, name).resolve() and require is_relative_to(base) before opening it.",
    "js": "Use path.resolve(base, name) and require the result to start with base + path.sep.",
    "shell": "Strip directories with basename, resolve with realpath, and require the result under the base dir.",
    "go": "Clean the path with filepath.Clean/filepath.Rel against the base and reject results outside it.",
    "java": "Normalize with base.resolve(name).normalize() and require startsWith(base).",
}
_SQL = {
    "default": "Use parameterized queries; never build SQL from string concatenation or formatting.",
    "python": "Pass values as query parameters (cursor.execute(sql, params)); never format them into the SQL string.",
    "js": "Use placeholders with a values array (or the ORM's query builder); never template values into SQL.",
    "go": "Use db.Query(sql, args...) with placeholders; never fmt.Sprintf values into SQL.",
    "java": "Use PreparedStatement with ? placeholders; never concatenate values into SQL.",
    "php": "Use PDO prepared statements with bound parameters; never interpolate values into SQL.",
}
_SSRF = {
    "default": "Allowlist the destination host and scheme before the request, and block internal addresses.",
    "python": "Parse the URL, allowlist scheme and host, and reject private/loopback addresses before requesting.",
    "js": "Parse with new URL(), allowlist protocol and host, and reject private/loopback addresses.",
}
_WEAK_HASH = {
    "default": "Use SHA-256 or stronger for integrity; for passwords use a password hash (argon2, bcrypt, scrypt).",
    "python": "Use hashlib.sha256 (or usedforsecurity=False for non-security checksums); hash passwords with argon2/bcrypt.",
}
_WEAK_RANDOM = {
    "default": "Use a cryptographically secure generator for tokens, keys and IDs.",
    "python": "Use the secrets module (secrets.token_urlsafe, secrets.choice) for security values.",
    "js": "Use crypto.randomBytes or crypto.getRandomValues instead of Math.random for security values.",
    "go": "Use crypto/rand instead of math/rand for security values.",
    "java": "Use java.security.SecureRandom instead of java.util.Random for security values.",
}
_CORS = {
    "default": "List the allowed origins explicitly instead of '*', and never combine '*' with credentials.",
    "python": "Set allow_origins to the dashboard's exact origins instead of ['*']; keep credentials off for '*'.",
    "js": "Pass an explicit origin allowlist to the CORS middleware instead of '*'.",
}
_TLS = {
    "default": "Keep certificate verification on; trust a private CA bundle instead of disabling checks.",
    "python": "Remove verify=False; pass verify='/path/to/ca.pem' for a private CA.",
    "js": "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0; supply the CA instead.",
    "go": "Remove InsecureSkipVerify: true; add the CA to the tls.Config RootCAs instead.",
}
_COOKIE = {
    "default": "Set Secure, HttpOnly and SameSite on session and auth cookies.",
}
_TIMING = {
    "default": "Compare secrets with a constant-time function.",
    "python": "Compare secrets with hmac.compare_digest instead of ==.",
    "js": "Compare secrets with crypto.timingSafeEqual instead of ===.",
    "go": "Compare secrets with subtle.ConstantTimeCompare.",
}
_OPEN_REDIRECT = {
    "default": "Redirect only to relative paths or an allowlist of hosts; reject absolute user-supplied URLs.",
}
_DESERIALIZE = {
    "default": "Never deserialize untrusted data with a code-executing format; use JSON or a schema-checked format.",
    "python": "Replace pickle/marshal on untrusted data with json or a schema-validated format.",
    "java": "Avoid ObjectInputStream on untrusted data; use JSON with a schema, or an allowlisting filter.",
    "php": "Replace unserialize on untrusted data with json_decode.",
}
_SECRET = {
    "default": "Remove the secret from the code, rotate it, and load it from the environment or a secret manager.",
}

_SECRET_DUMMY = "Remove the hard-coded credential and load it from the environment or a secret manager."
_DYNAMIC_CODE = {
    "default": "Remove dynamic code execution; call the needed function directly or parse data with a safe parser.",
    "python": "Replace exec/eval with direct calls, a dispatch dict, or ast.literal_eval for literals.",
    "js": "Replace eval/new Function/string timers with direct function calls or JSON.parse.",
}
_DEAD_CODE = "Delete it if nothing outside this repo uses it; otherwise add {comment} skylos: ignore[{rule}] with a reason."

RULE_FIXES: dict[str, dict[str, str]] = {
    "SKY-A101": {
        "default": "Restore the original assertion, or explain in the PR why the check is weaker."
    },
    "SKY-A102": {
        "default": "Add a test that exercises the changed high-risk code path."
    },
    "SKY-A103": {
        "default": "Keep CI permissions at the minimum the job needs; revert the widened scope."
    },
    "SKY-A104": {
        "default": "Keep the public CLI flags/commands compatible, or document the breaking change."
    },
    "SKY-A105": {
        "default": "Add the auth guard the route contract requires before merging."
    },
    "SKY-A106": {
        "default": "Confirm the new dependency version exists and is intended; pin the reviewed version."
    },
    "SKY-A110": {
        "default": "Restore the deleted test, or replace it with one that covers the same behaviour."
    },
    "SKY-A111": {
        "default": "Remove the new skip, or link the issue that tracks re-enabling the test."
    },
    "SKY-A112": {
        "default": "Revert the loosened test settings (timeouts, markers, tolerances) or justify them."
    },
    "SKY-A113": {
        "default": "Fix the failing tests before merging; run them locally with the command Skylos used."
    },
    "SKY-A114": {
        "default": "Revert the Skylos settings or hook change, or get it reviewed separately."
    },
    "SKY-A115": {
        "default": "Compute the result instead of hard-coding the value the test expects."
    },
    "SKY-A116": {
        "default": "Remove the test-environment check so production and tests run the same code."
    },
    "SKY-A117": {
        "default": "Make the comparison check the real values instead of always passing."
    },
    "SKY-A118": {
        "default": "Fix the finding instead of suppressing it, or add a reason next to the ignore."
    },
    "SKY-A119": {
        "default": "Revert the weakened linter/scanner settings or get them reviewed separately."
    },
    "SKY-A120": {"default": "Add a test that runs the changed line."},
    "SKY-A121": {
        "default": "Restore the CI check that was removed or made non-blocking."
    },
    "SKY-A122": {
        "default": "Revert the AI-reviewer settings change or get it reviewed separately."
    },
    "SKY-A125": {
        "default": "Remove the scanner suppression marker and fix the underlying finding."
    },
    "SKY-A135": {
        "default": "Delete the code this change left unused, or wire it back in."
    },
    "SKY-A136": {"default": "Call the new code from where it is needed, or remove it."},
    "SKY-A137": {
        "default": "Use the new code from production code, or remove it with its tests."
    },
    "SKY-C303": {
        "default": "Group related parameters into an object, or make optional ones keyword-only."
    },
    "SKY-C304": {
        "default": "Split the function into smaller functions with one job each."
    },
    "SKY-C401": {"default": "Extract the duplicated code into one shared function."},
    "SKY-CIRC": {
        "default": "Break the import cycle: move the shared code to a module both can import."
    },
    "SKY-D200": {
        "default": "Replace the dangerous call with a safe API, or validate its input against an allowlist."
    },
    "SKY-D201": _DYNAMIC_CODE,
    "SKY-D202": _DYNAMIC_CODE,
    "SKY-D203": _UNTRUSTED_COMMAND,
    "SKY-D204": _DESERIALIZE,
    "SKY-D205": _DESERIALIZE,
    "SKY-D206": {
        "default": "Load YAML with a safe loader that cannot construct objects.",
        "python": "Use yaml.safe_load (or Loader=yaml.SafeLoader) instead of yaml.load.",
    },
    "SKY-D207": _WEAK_HASH,
    "SKY-D208": _WEAK_HASH,
    "SKY-D209": {
        **_UNTRUSTED_COMMAND,
        "python": "Pass an argument list and drop shell=True; allowlist any user-controlled value.",
    },
    "SKY-D210": _TLS,
    "SKY-D211": _SQL,
    "SKY-D212": _UNTRUSTED_COMMAND,
    "SKY-D215": _PATH_TRAVERSAL,
    "SKY-D216": _SSRF,
    "SKY-D217": _SQL,
    "SKY-D218": {
        "default": "Allowlist http/https before opening a dynamic URL so file:// and other schemes are rejected.",
        "python": "Check urllib.parse.urlparse(url).scheme in {'http', 'https'} before urlopen.",
    },
    "SKY-D222": {
        "default": "The imported package does not exist: fix the name, or remove the import."
    },
    "SKY-D223": {
        "default": "Declare the package in the project's dependency manifest.",
        "python": "Add the package to pyproject.toml (or requirements.txt) and lock it.",
        "js": "Add the package to package.json dependencies and update the lockfile.",
    },
    "SKY-D224": {
        "default": "Use a function or argument the installed library actually provides."
    },
    "SKY-D225": {"default": "Pin a dependency version that exists on the registry."},
    "SKY-D226": {
        "default": "Escape untrusted content instead of marking it safe; sanitize HTML with an allowlist."
    },
    "SKY-D227": {
        "default": "Render through the template engine with auto-escaping; do not build templates from input."
    },
    "SKY-D228": {
        "default": "Build HTML with auto-escaping templates or textContent, not string concatenation."
    },
    "SKY-D230": _OPEN_REDIRECT,
    "SKY-D231": _CORS,
    "SKY-D232": {
        "default": "Verify JWT signatures with a fixed algorithm list and key; reject 'none'."
    },
    "SKY-D233": _DESERIALIZE,
    "SKY-D234": {
        "default": "Copy only an explicit allowlist of fields from the request into the model."
    },
    "SKY-D235": {
        "default": "Do not run remote commands built from input; use a fixed command with checked arguments."
    },
    "SKY-D240": {
        "default": "Remove instructions aimed at the model from the MCP tool description."
    },
    "SKY-D241": {
        "default": "Require authentication on the MCP transport, or bind it to localhost only."
    },
    "SKY-D242": {
        "default": "Narrow the MCP resource URI pattern to the paths the tool needs."
    },
    "SKY-D243": {
        "default": "Add authentication before exposing the MCP server on the network."
    },
    "SKY-D244": {
        "default": "Move the secret out of the MCP tool parameters into server-side configuration."
    },
    "SKY-D245": {
        "default": "Use a static require/import path, or map input to an allowlist of modules."
    },
    "SKY-D246": {"default": "Decode JWTs only with signature verification enabled."},
    "SKY-D247": _CORS,
    "SKY-D248": {
        "default": "Move the internal URL into configuration instead of the code."
    },
    "SKY-D250": _WEAK_RANDOM,
    "SKY-D251": {
        "default": "Do not log secrets or personal data; log an identifier or a redacted value."
    },
    "SKY-D252": _COOKIE,
    "SKY-D253": _TIMING,
    "SKY-D254": {
        "default": "Re-check authorization on the server instead of trusting values stored in the session."
    },
    "SKY-D260": {
        "default": "Treat the text as data: keep it out of agent instructions, or mark it as untrusted input."
    },
    "SKY-D261": {
        "default": "Separate untrusted input from instructions and validate it before it reaches the prompt."
    },
    "SKY-D262": {
        "default": "Validate model output against a schema before executing, rendering or storing it."
    },
    "SKY-D263": {
        "default": "Remove secrets and personal data from the prompt, or redact them first."
    },
    "SKY-D264": {
        "default": "Give the agent only the tools and permissions the task needs; require approval for writes."
    },
    "SKY-D265": {
        "default": "Load models with weights-only/safetensors formats; never unpickle untrusted model files."
    },
    "SKY-D266": {
        "default": "Remove injected instructions from the AI configuration file and review its source."
    },
    "SKY-D267": {"default": "Set max tokens, timeouts and rate limits on model calls."},
    "SKY-D270": {
        "default": "Encrypt sensitive data at rest, or store a token/hash instead of the value."
    },
    "SKY-D271": {
        "default": "Return a generic error to the client and log the details server-side."
    },
    "SKY-D280": {
        "default": "Check the session and permissions at the start of the mutating API route."
    },
    "SKY-D281": _SQL,
    "SKY-D282": {
        "default": "Verify the webhook signature with a constant-time comparison before processing it."
    },
    "SKY-D290": {
        "default": "Avoid pull_request_target/workflow_run with untrusted checkout; use pull_request instead."
    },
    "SKY-D291": {
        "default": "Set top-level permissions: contents: read and grant more only to the job that needs it."
    },
    "SKY-D292": {
        "default": "Pin the action to a full commit SHA (uses: owner/repo@<40-char sha>)."
    },
    "SKY-D293": {"default": "Add persist-credentials: false to actions/checkout."},
    "SKY-D294": {
        "default": "Pass ${{ }} values through env: and quote them in the script instead of inlining them."
    },
    "SKY-D295": {
        "default": "Do not run untrusted workflows on self-hosted runners; use GitHub-hosted runners."
    },
    "SKY-D296": {"default": "Pin the container image by digest (image@sha256:...)."},
    "SKY-D297": {
        "default": "Replace secrets: inherit with the specific secrets the called workflow needs."
    },
    "SKY-D298": {
        "default": "Expose only the secrets this job uses, not the whole secrets context."
    },
    "SKY-D299": {
        "default": "Move the secret into a protected GitHub environment used by this job."
    },
    "SKY-D300": {
        "default": "Validate values before writing to GITHUB_ENV/GITHUB_PATH, or avoid writing input there."
    },
    "SKY-D301": {"default": "Move the container registry credential into a secret."},
    "SKY-D302": {
        "default": "Request a GitHub App token scoped to the repositories and permissions needed."
    },
    "SKY-D303": {
        "default": "Compare exact values instead of contains() on a string the actor controls."
    },
    "SKY-D304": {
        "default": "Check the bot by a non-spoofable field (user id or app slug), not the actor name."
    },
    "SKY-D305": {
        "default": "Write the if: condition on one line, or with explicit ${{ }} so it is not always true."
    },
    "SKY-D306": {
        "default": "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use environment files instead."
    },
    "SKY-D307": {"default": "Give the workflow and its jobs a name."},
    "SKY-D308": {
        "default": "Do not restore caches written by untrusted runs in release jobs; key caches per trust level."
    },
    "SKY-D309": {
        "default": "Move secrets from workflow-level env to the step that uses them."
    },
    "SKY-D310": {
        "default": "Do not run repository build scripts in a job that holds id-token: write."
    },
    "SKY-D311": {
        "default": "Upload only the files you need, and exclude credentials and .git."
    },
    "SKY-D312": {
        "default": "Install with --ignore-scripts (npm ci --ignore-scripts) in privileged jobs."
    },
    "SKY-D313": {"default": "Set timeout-minutes on the privileged job."},
    "SKY-D314": {"default": "Pin the GitLab CI image by digest."},
    "SKY-D315": {
        "default": "Pin the external include to a commit SHA or a protected ref."
    },
    "SKY-D316": {"default": "Move the secret into a masked, protected CI/CD variable."},
    "SKY-D317": {"default": "Do not eval CI variables a merge request can set."},
    "SKY-D318": {"default": "Enable TLS for Docker-in-Docker (DOCKER_TLS_CERTDIR)."},
    "SKY-D319": {
        "default": "Do not run repository scripts in a job that holds an OIDC token."
    },
    "SKY-D320": {
        "default": "Use separate cache keys for release jobs so untrusted pipelines cannot seed them."
    },
    "SKY-D321": {"default": "Set timeout on the privileged GitLab job."},
    "SKY-D322": {"default": "Use fixed runner tags; do not take them from variables."},
    "SKY-D323": {
        "default": "Rename the variable so it is clearly a secret and mark it masked."
    },
    "SKY-D324": {
        "default": "Reject symlinks and check the resolved path stays in the allowed directory before writing.",
        "python": "Open with os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW) after a containment check.",
    },
    "SKY-D325": {
        "default": "Require a regular file inside the allowed directory and cap how much is read.",
        "python": "Check the resolved path is under the base and a regular file, then read with a size limit.",
    },
    "SKY-D326": {
        "default": "Check every archive member path stays inside the destination before extracting it.",
        "python": "Use tarfile's filter='data' (or check each member's resolved path) before extracting.",
    },
    "SKY-D327": {
        "default": "Remove the command that sends files, environment or credentials to a remote host."
    },
    "SKY-D328": {
        "default": "Download the script, verify its checksum or signature, then run the saved file."
    },
    "SKY-D329": {
        "default": "Scope the destructive command to an explicit, validated path; never rm -rf a variable alone."
    },
    "SKY-D330": {
        "default": "Drop privileged: true and grant only the capabilities or devices required."
    },
    "SKY-D331": {"default": "Map only the specific host devices the service needs."},
    "SKY-D332": {
        "default": "Use a bridge network with published ports instead of network_mode: host."
    },
    "SKY-D333": {
        "default": "Run the service as a dedicated user (User= in the unit file)."
    },
    "SKY-D334": {"default": "Point ExecStart at a root-owned, non-writable path."},
    "SKY-D335": {
        "default": "Add systemd sandboxing (NoNewPrivileges, ProtectSystem, PrivateTmp)."
    },
    "SKY-D336": {
        "default": "Remove the broad capabilities from the unit; grant only what the service needs."
    },
    "SKY-D337": {
        "default": "Install from the default registry, or pin the private index with hashes."
    },
    "SKY-D338": {
        "default": "Do not read host credential stores, SSH keys or browser data from the script."
    },
    "SKY-D339": {
        "default": "Do not change shell profiles, cron or global config from the script; document the step instead."
    },
    "SKY-D340": {
        "default": "Publish packages only from the approved release workflow."
    },
    "SKY-D341": {
        "default": "Pin the tool version (and hash) instead of running the latest package from the registry."
    },
    "SKY-D342": {
        "default": "Download with a checksum check (ADD --checksum=sha256:...) or COPY a vetted file."
    },
    "SKY-D343": {
        "default": "Pass build secrets with RUN --mount=type=secret instead of ARG/ENV values."
    },
    "SKY-D344": {
        "default": "Remove the bidirectional Unicode control characters from the source."
    },
    "SKY-D345": {
        "default": "Pin the Hugging Face model or dataset to a commit revision."
    },
    "SKY-D346": {"default": "Turn Flask debug mode off outside local development."},
    "SKY-D347": {
        "default": "Do not start logging.config.listen on a reachable port; load logging config from a file."
    },
    "SKY-D348": {
        "default": "Create temporary files atomically with a secure temp-file API.",
        "python": "Use tempfile.NamedTemporaryFile or mkstemp instead of tempfile.mktemp.",
    },
    "SKY-D349": {
        "default": "Render fixed templates with user data as variables; never compile templates from input."
    },
    "SKY-D350": {
        "default": "Gate the AI agent job on a trusted actor or label before it runs on untrusted events."
    },
    "SKY-D351": {"default": "Restore the write-access check before the AI agent runs."},
    "SKY-D352": {
        "default": "Remove shell access from the AI agent on untrusted triggers, or gate it on a trusted actor."
    },
    "SKY-D353": {
        "default": "Pass PR/issue text to the agent as data via env, not inside its prompt instructions."
    },
    "SKY-D354": {
        "default": "Upgrade the AI agent action past the published advisory and pin it by SHA."
    },
    "SKY-D360": {
        "default": "Set insecure-external-code-execution: deny in dependabot.yml."
    },
    "SKY-D361": {"default": "Set a Dependabot cooldown of at least seven days."},
    "SKY-D362": {
        "default": "Do not print decoded secrets; add ::add-mask:: before using them."
    },
    "SKY-D363": {"default": "Use a plain, readable action path and expression."},
    "SKY-D364": {
        "default": "Publish with trusted publishing (OIDC) and delete the long-lived token."
    },
    "SKY-D510": {
        "default": "Reject __proto__, constructor and prototype keys before merging objects."
    },
    "SKY-DEP001": {
        "default": "Add the required auth guard to the route before exposing it externally."
    },
    "SKY-DEP002": {
        "default": "Turn off the Flask debugger in the externally exposed deployment."
    },
    "SKY-DEP003": {"default": "Run the externally routed app without reload mode."},
    "SKY-E002": {
        "default": "Delete the empty file, or add the code it was meant to hold."
    },
    "SKY-E003": {
        "default": "Delete the file if nothing imports it; otherwise add it as an entry point."
    },
    "SKY-F101": {
        "default": "Follow the framework's recommended handler pattern described in the message."
    },
    "SKY-F102": {
        "default": "Add an auth/permission dependency to the route, or confirm it is meant to be public."
    },
    "SKY-G203": {
        "default": "Move the defer into a function called per iteration, or close the resource explicitly."
    },
    "SKY-G206": {
        "default": "Avoid package unsafe unless required; document and test the pointer use."
    },
    "SKY-G207": {
        "default": "Use crypto/sha256 or stronger instead of crypto/md5 for security uses."
    },
    "SKY-G208": {
        "default": "Use crypto/sha256 or stronger instead of crypto/sha1 for security uses."
    },
    "SKY-G209": _WEAK_RANDOM,
    "SKY-G210": _TLS,
    "SKY-G211": _SQL,
    "SKY-G212": _UNTRUSTED_COMMAND,
    "SKY-G215": _PATH_TRAVERSAL,
    "SKY-G216": _SSRF,
    "SKY-G220": _OPEN_REDIRECT,
    "SKY-G221": _COOKIE,
    "SKY-G260": {
        "default": "Close the resource with defer x.Close() right after checking the error."
    },
    "SKY-G280": {"default": "Set tls.Config MinVersion to tls.VersionTLS12 or higher."},
    "SKY-GPU000": {
        "default": "Complete the GPU release contract fields the message lists."
    },
    "SKY-GPU001": {
        "default": "Use a CUDA image the fleet's NVIDIA driver supports, or upgrade the driver."
    },
    "SKY-GPU002": {
        "default": "Add the target GPU architecture to the build's CUDA arch list."
    },
    "SKY-GPU003": {"default": "Build the TensorRT engine on (or for) each target GPU."},
    "SKY-L001": {
        "default": "Use None as the default and create the mutable value inside the function.",
        "js": "Create a new object or array inside the function instead of sharing a default.",
    },
    "SKY-L002": {
        "default": "Catch the specific exceptions you expect, and log or re-raise the rest.",
        "python": "Catch specific exceptions instead of a bare except: (at least except Exception).",
    },
    "SKY-L003": {
        "default": "Use the correct comparison (is None / == value) as the message describes."
    },
    "SKY-L004": {"default": "Wrap only the statement that can fail in the try block."},
    "SKY-L005": {
        "default": "Use the caught exception (log it) or drop the variable.",
        "python": "Log the exception, or write except SomeError: without 'as e'.",
    },
    "SKY-L006": {
        "default": "Rename the inner loop variable so it does not shadow the outer one."
    },
    "SKY-L007": {"default": "Log or handle the error instead of silently ignoring it."},
    "SKY-L008": {
        "default": "Close the resource deterministically.",
        "python": "Open the resource in a with statement so it is always closed.",
        "js": "Close the resource in a finally block (or use a using/await using declaration).",
        "go": "Call defer x.Close() right after the open succeeds.",
        "java": "Use try-with-resources so the resource is always closed.",
    },
    "SKY-L009": {
        "default": "Remove the debug leftover (print/breakpoint/console.log) before shipping."
    },
    "SKY-L010": {
        "default": "Resolve the security TODO or open a tracked issue for it."
    },
    "SKY-L011": {
        "default": "Re-enable the security control, or document why it is safe to disable here."
    },
    "SKY-L012": {
        "default": "Fix the reference: the symbol it names does not exist in the project."
    },
    "SKY-L013": _WEAK_RANDOM,
    "SKY-L014": {"default": _SECRET_DUMMY},
    "SKY-L016": {
        "default": "Define the configuration key, or read it with an explicit default."
    },
    "SKY-L017": {
        "default": "Return a generic error message to the client and log the exception server-side."
    },
    "SKY-L020": {
        "default": "Use the narrowest file mode that works (for example 0o600 or 0o644, never 0o777)."
    },
    "SKY-L021": {"default": "Restore the security control the change removed."},
    "SKY-L023": {
        "default": "Fix the decorator name: it does not exist in the imported module."
    },
    "SKY-L024": {
        "default": "Update the mock to match the current function, or remove it."
    },
    "SKY-L026": {
        "default": "Finish the placeholder implementation or default before shipping."
    },
    "SKY-L027": {"default": "Move the repeated literal into one named constant."},
    "SKY-L028": {
        "default": "Reduce the number of return points (guard clauses first, one result path)."
    },
    "SKY-L029": {
        "default": "Pass the flag by keyword, or make the parameter keyword-only."
    },
    "SKY-L030": {
        "default": "Catch a narrower exception, or log and re-raise instead of ignoring it."
    },
    "SKY-L031": {
        "default": "Set an explicit timeout on the network call.",
        "python": "Pass timeout=... to the request (for example requests.get(url, timeout=10)).",
    },
    "SKY-L032": {
        "default": "Replace the mock or placeholder data with real data or configuration."
    },
    "SKY-L033": {
        "default": "Remove the statement or use its result; it has no effect."
    },
    "SKY-L034": {
        "default": "Build independent values with a comprehension instead of repeating a mutable element."
    },
    "SKY-L035": {
        "default": "Disable only the specific ESLint rules needed, on the lines that need it."
    },
    "SKY-L036": {"default": "Move the import to the top of the module."},
    "SKY-L037": {"default": "Return the condition (or not condition) directly."},
    "SKY-L038": {
        "default": "Use a format spec ({x!r} or {x:.2f}) instead of calling the conversion inside the f-string."
    },
    "SKY-L039": {"default": "Remove the except clause that only re-raises."},
    "SKY-P401": {
        "default": "Read in bounded chunks, or check the size before reading everything."
    },
    "SKY-P402": {"default": "Compute the expensive value once, outside the loop."},
    "SKY-P403": {
        "default": "Index one side in a dict or set to avoid the nested scan, if all pairs are not needed."
    },
    "SKY-P404": {
        "default": "Paginate or limit the query instead of loading every row."
    },
    "SKY-Q301": {
        "default": "Split the function: extract branches into helpers or use a lookup table."
    },
    "SKY-Q302": {
        "default": "Flatten the nesting with early returns or extracted helpers."
    },
    "SKY-Q305": {
        "default": "Merge the duplicate branches, or make them do the intended different things."
    },
    "SKY-Q306": {
        "default": "Simplify the nested logic: early returns, extracted helpers, fewer boolean chains."
    },
    "SKY-Q401": {
        "default": "Use the async version of the call, or run it in a thread executor."
    },
    "SKY-Q402": {
        "default": "Start the awaits together (asyncio.gather / Promise.all) when they are independent."
    },
    "SKY-Q403": {"default": "Always acquire the locks in the same order."},
    "SKY-Q404": {
        "default": "Guard the shared state with a lock, or keep it per thread."
    },
    "SKY-Q405": {
        "default": "Do not pass an async function to new Promise; await the work directly."
    },
    "SKY-Q406": {
        "default": "Use for...of with await (or Promise.all) instead of an async forEach callback."
    },
    "SKY-Q407": {"default": "Await the mapped promises with Promise.all."},
    "SKY-Q501": {"default": "Split the class by responsibility into smaller classes."},
    "SKY-Q502": {"default": "Split the file into modules by responsibility."},
    "SKY-Q701": {
        "default": "Reduce dependencies: depend on fewer classes, or pass collaborators in."
    },
    "SKY-Q702": {
        "default": "Split the class so each part's methods use the same fields."
    },
    "SKY-Q801": {
        "default": "Depend on this module through a stable interface, or make it more stable."
    },
    "SKY-Q802": {
        "default": "Balance the module: add abstractions to concrete stable modules, or reduce dependants."
    },
    "SKY-Q803": {
        "default": "Move the module out of the zone: add an interface or reduce its dependants."
    },
    "SKY-Q804": {
        "default": "Depend on an abstraction instead of the more unstable module."
    },
    "SKY-Q805": {
        "default": "Move the import so it follows the configured layer rules."
    },
    "SKY-Q806": {"default": "Rename the identifier so it says what it holds."},
    "SKY-R101": {"default": "Add a mypy or pyright configuration for the project."},
    "SKY-R102": {
        "default": "Add a Ruff (or Flake8/Pylint) configuration for the project."
    },
    "SKY-R103": {
        "default": "Add a [tool.skylos.gate] section with the limits CI should enforce."
    },
    "SKY-R104": {
        "default": "Add a .pre-commit-config.yaml with the checks you run locally."
    },
    "SKY-R105": {"default": "Add a tsconfig.json with strict type checking."},
    "SKY-S101": _SECRET,
    "SKY-S102": {
        "default": "Move the secret to the server; only expose public keys to client code."
    },
    "SKY-SC001": {
        "default": "Fix the contract issue the message names before deploying."
    },
    "SKY-SCA-LIC001": {
        "default": "Replace the dependency, or record a license exception your policy allows."
    },
    "SKY-T101": {"default": "Add type annotations to the parameters."},
    "SKY-T102": {"default": "Add a return type annotation."},
    "SKY-T103": {
        "default": "Replace the chained assertion with a type guard or validation."
    },
    "SKY-T104": {
        "default": "Remove the @ts-ignore/@ts-nocheck and fix the type error it hides."
    },
    "SKY-T105": {
        "default": "Validate parsed JSON with a schema before asserting its type."
    },
    "SKY-T106": {
        "default": "Give the exported API a precise type instead of any/unknown casts."
    },
    "SKY-UC001": {
        "default": "Remove the unreachable code, or fix the condition that makes it unreachable."
    },
    "SKY-UC002": {
        "default": "Remove the statement after the return/raise/break, or move it before."
    },
}

_DEAD_CODE_RULES = frozenset(
    {"SKY-U001", "SKY-U002", "SKY-U003", "SKY-U004", "SKY-U005", "SKY-U006"}
)
_CATEGORY_RULES = {
    "unused_functions": "SKY-U001",
    "unused_imports": "SKY-U002",
    "unused_variables": "SKY-U003",
    "unused_classes": "SKY-U004",
    "unused_parameters": "SKY-U006",
    "unused_files": "SKY-E002",
    "secrets": "SKY-S101",
    "circular_dependencies": "SKY-CIRC",
}
_IMPERATIVE = re.compile(
    r"^(?:use|avoid|pass|add|remove|replace|validate|check|require|reject|resolve|"
    r"set|move|declare|pin|narrow|split|send|return|log|call|open|close|make|"
    r"keep|restrict|escape|sanitize|verify|store|read|load|limit|do not|never|"
    r"consider|establish|reduce|write|drop|delete|define|rename|wrap|guard)\b",
    re.IGNORECASE,
)


def finding_rule_id(finding: Mapping, category=None) -> str:
    rule_id = str(finding.get("rule_id") or finding.get("id") or "").strip().upper()
    if rule_id:
        return rule_id
    return _CATEGORY_RULES.get(str(category or ""), "")


def finding_language(finding: Mapping) -> str:
    declared = str(finding.get("language") or "").strip().lower()
    if declared in _LANGUAGE_NAMES:
        return _LANGUAGE_NAMES[declared]
    path = str(finding.get("file") or finding.get("file_path") or "")
    name = PurePath(path).name.lower()
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    return _SUFFIX_LANGUAGES.get(PurePath(name).suffix, "other")


def rule_docs_url(rule_id) -> str:
    anchor = RULE_DOCS_ANCHORS.get(str(rule_id or "").strip().upper())
    if anchor:
        return f"{DOCS_PAGE}#{anchor}"
    return DOCS_PAGE


def _message_advice(message: str) -> str | None:
    text = " ".join(str(message or "").split())
    if not text:
        return None
    clauses = [part.strip() for part in re.split(r";\s+|(?<=[.!?])\s+", text)]
    for clause in reversed(clauses[1:]):
        if _IMPERATIVE.match(clause):
            clause = clause.rstrip(".")
            return clause[0].upper() + clause[1:] + "."
    return None


def finding_fix(finding: Mapping, category=None) -> str:
    """One line saying what to change, correct for the finding's language."""
    if not isinstance(finding, Mapping):
        return ""
    rule_id = finding_rule_id(finding, category)
    language = finding_language(finding)
    if rule_id in _DEAD_CODE_RULES:
        comment = _COMMENT_PREFIX.get(language, "#")
        return _DEAD_CODE.format(comment=comment, rule=rule_id)
    fixes = RULE_FIXES.get(rule_id)
    if fixes:
        return fixes.get(language) or fixes["default"]
    advice = _message_advice(finding.get("message"))
    if advice:
        return advice
    if str(category or "") == "dependency_vulnerabilities" or rule_id.startswith(
        "SKY-SCA"
    ):
        fixed = (finding.get("metadata") or {}).get("fixed_version")
        if fixed:
            return f"Upgrade the package to {fixed} or later."
        return "Upgrade to a version without the advisory, or replace the package."
    return "Review the finding against the rule docs, then fix it or suppress it with a reason."
