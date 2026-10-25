from __future__ import annotations

import dataclasses
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

KEY_SOURCE_LABELS = {
    "env": "project token from SKYLOS_TOKEN",
    "ci": "GitHub Actions or GitLab CI identity",
    "link": "login token for this repo's linked project (.skylos/link.json)",
    "saved": "your saved login token; this repo is not linked (skylos project use links it)",
}

_PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_DEFAULT_BRANCH_SOURCES = {"repository", "assumed"}


@dataclass(frozen=True)
class UploadDestination:
    key_source: str
    project_id: str | None = None
    project_name: str | None = None
    project_repo: str | None = None
    local_repo: str | None = None
    branch: str | None = None
    commit: str | None = None
    default_branch: str | None = None
    default_branch_source: str | None = None

    @property
    def repo_mismatch(self) -> bool:
        if not self.project_repo or not self.local_repo:
            return False
        return self.project_repo.casefold() != self.local_repo.casefold()

    @property
    def on_default_branch(self) -> bool | None:
        if not self.branch or not self.default_branch:
            return None
        return self.branch == self.default_branch


def resolve_upload_destination(
    project_root: str | Path,
    *,
    token: str | None = None,
    whoami=None,
    git_info=None,
) -> UploadDestination:
    from skylos import api
    from skylos.core.review_decisions import (
        _git_remote_identity,
        _normalize_repository_identity,
    )

    if token is None:
        token = api.get_project_token()
    key_source = _key_source(token)
    project: dict = {}
    if token and key_source != "ci":
        lookup = whoami or api.get_project_info
        info = lookup(token)
        if (
            isinstance(info, dict)
            and info.get("ok")
            and isinstance(info.get("project"), dict)
        ):
            project = info["project"]

    commit, branch, _actor, _ci = (git_info or api.get_git_info)()
    git_root = api.get_git_root()
    local_repo = None
    if git_root:
        local_repo = _git_remote_identity(Path(git_root))

    return UploadDestination(
        key_source=key_source,
        project_id=_clean_project_id(project.get("id")),
        project_name=_clean_text(project.get("name")),
        project_repo=_normalize_repository_identity(project.get("repo_url")),
        local_repo=local_repo,
        branch=_clean_ref(branch),
        commit=_clean_ref(commit),
    )


def with_cloud_destination(
    dest: UploadDestination, upload_resp: dict
) -> UploadDestination:
    reported = upload_resp.get("destination")
    if not isinstance(reported, dict):
        return dest
    changes = {}
    branch = _clean_ref(reported.get("branch"))
    if branch:
        changes["branch"] = branch
    default_branch = _clean_ref(reported.get("default_branch"))
    if default_branch:
        changes["default_branch"] = default_branch
        source = reported.get("default_branch_source")
        if source in _DEFAULT_BRANCH_SOURCES:
            changes["default_branch_source"] = source
    project_id = _clean_project_id(reported.get("project_id"))
    if project_id and not dest.project_id:
        changes["project_id"] = project_id
    return dataclasses.replace(dest, **changes)


def _key_source(token: str | None) -> str:
    if not token:
        return "none"
    if os.getenv("SKYLOS_TOKEN"):
        return "env"
    if token.startswith(("oidc:", "gitlab_oidc:")):
        return "ci"
    from skylos import api

    repo_root = api._get_repo_root_for_link()
    link = api._read_json(repo_root / api.LINK_FILE) or {}
    linked_project_id = api._linked_project_id_for_current_path(link, repo_root)
    if linked_project_id:
        creds = api._read_json(api.GLOBAL_CREDS_FILE) or {}
        entry = (creds.get("tokens") or {}).get(linked_project_id) or {}
        if entry.get("token") == token:
            return "link"
    return "saved"


def _clean_text(value) -> str | None:
    if not isinstance(value, str):
        return None
    text = "".join(char for char in value[:200] if char.isprintable()).strip()
    return text or None


def _clean_ref(value) -> str | None:
    text = _clean_text(value)
    if text is None or text == "unknown":
        return None
    return text


def _shown(value) -> str:
    text = _clean_text(value)
    if text is None:
        return "unknown"
    return text


def _printable(line: str) -> str:
    return "".join(char for char in line if char.isprintable())


def _clean_project_id(value) -> str | None:
    if isinstance(value, str) and _PROJECT_ID.fullmatch(value):
        return value
    return None


def _short_commit(commit: str | None) -> str | None:
    if not commit:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{12,64}", commit):
        return commit[:7]
    return commit


def project_label(dest: UploadDestination) -> str:
    if dest.project_name:
        return dest.project_name
    if dest.key_source == "ci":
        return "the project your CI identity is connected to"
    return "unknown (Skylos Cloud did not name the project for this token)"


def branch_label(dest: UploadDestination) -> str:
    text = dest.branch or "unknown branch"
    short = _short_commit(dest.commit)
    if short:
        text = f"{text} @ {short}"
    if dest.on_default_branch is True:
        return f"{text} (the default branch)"
    if dest.on_default_branch is False:
        return f"{text} (not the default branch, {dest.default_branch})"
    return text


def destination_lines(dest: UploadDestination) -> list[str]:
    lines = [
        f"Skylos Cloud project: {project_label(dest)}",
        f"  Token:  {_shown(KEY_SOURCE_LABELS.get(dest.key_source, dest.key_source))}",
        f"  Branch: {branch_label(dest)}",
    ]
    if dest.repo_mismatch:
        lines.append(
            f"  This token's project is connected to {_shown(dest.project_repo)}, "
            f"but this repo is {_shown(dest.local_repo)}."
        )
    return [_printable(line) for line in lines]


UPLOAD_CONTENTS_LINE = (
    "  Sends:  findings with file paths and code snippets of up to 7 lines "
    "(none for secrets), the branch, the commit, the git author email of "
    "each flagged line, and a map of your functions and classes (names, files, "
    "lines, sizes, which calls which). Not your repository."
)


def mismatch_refusal_lines(dest: UploadDestination) -> list[str]:
    lines = [
        f"Not uploaded: this repo is {_shown(dest.local_repo)}, but your saved login token "
        f"belongs to project {project_label(dest)} ({_shown(dest.project_repo)}).",
        "  Uploading would put this repo's findings into that project.",
        "  Pick the right project for this repo: skylos project use",
        "  Or upload with a project token of that project: SKYLOS_TOKEN=<token> skylos . --upload",
    ]
    return [_printable(line) for line in lines]


def should_refuse_upload(dest: UploadDestination) -> bool:
    return dest.key_source == "saved" and dest.repo_mismatch


def receipt_note(dest: UploadDestination, upload_trust) -> str | None:
    default = dest.default_branch or "the default branch"
    if dest.on_default_branch is False:
        return (
            f"This is not {default}: Overview shows its gate when you pick {dest.branch} "
            f"in the branch menu, but the project verdict follows {default} only."
        )
    if dest.on_default_branch is True and upload_trust == "unverified":
        return (
            f"This is {default}, but a login-token upload is unverified: it does not "
            "set the project verdict or mark issues fixed."
        )
    if dest.default_branch is None:
        return (
            "Skylos Cloud did not report its default branch; only the default "
            "branch sets the project verdict."
        )
    if dest.default_branch_source == "assumed":
        return (
            f"Skylos Cloud assumed {default} is the default branch because it could "
            "not read it from GitHub or GitLab."
        )
    return None


def _receipt_branch_label(dest: UploadDestination) -> str:
    text = dest.branch or "unknown branch"
    short = _short_commit(dest.commit)
    if short:
        text = f"{text} @ {short}"
    default_name = "the default branch"
    if dest.default_branch_source == "assumed":
        default_name = "the assumed default branch"
    if dest.on_default_branch is True:
        return f"{text} ({default_name})"
    if dest.on_default_branch is False:
        return f"{text} (not {default_name}, {dest.default_branch})"
    return text


def _branch_query(dest: UploadDestination) -> str:
    if not dest.branch or dest.on_default_branch is True:
        return ""
    return f"?branch={quote(dest.branch, safe='')}"


def receipt_lines(
    dest: UploadDestination, upload_resp: dict, base_url: str
) -> list[str]:
    dest = with_cloud_destination(dest, upload_resp)
    base = base_url.rstrip("/")
    summary = f"Branch: {_receipt_branch_label(dest)}"
    if dest.project_id:
        project_path = f"{base}/dashboard/projects/{quote(dest.project_id, safe='')}"
        query = _branch_query(dest)
        summary = (
            f"{summary} · Overview: {project_path}{query}"
            f" · Issues: {project_path}/issues{query}"
        )
    lines = ["", summary]
    note = receipt_note(dest, upload_resp.get("upload_trust"))
    if note:
        lines.append(note)
    return [_printable(line) for line in lines]
