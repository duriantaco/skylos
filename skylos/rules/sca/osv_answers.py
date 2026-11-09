"""Last good OSV answers for exact package versions, used only when OSV fails.

Live answers always win. The store lives in the user's cache directory, never
inside a scanned repository, so a repository cannot decide its own result. A
scan that relied on it is never reported as complete: advisories published
since the answer was saved are missing.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink
from skylos.rules.sca.osv_client import _valid_advisory, is_valid_advisory_id

logger = logging.getLogger(__name__)

SAVED_ANSWERS_KEY = "__saved_answers__"
STORE_VERSION = 1
MAX_ANSWER_AGE_SECONDS = 7 * 24 * 3600
MAX_FUTURE_SKEW_SECONDS = 300
MAX_STORE_BYTES = 32 * 1024 * 1024
MAX_SAVED_PACKAGES = 20_000


def answer_key(dependency: dict) -> str:
    return f"{dependency['ecosystem']}:{dependency['name']}:{dependency['version']}"


def store_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "skylos" / "osv-answers.json"
    return Path.home() / ".cache" / "skylos" / "osv-answers.json"


def _fresh(saved_at: object, now: float) -> bool:
    if isinstance(saved_at, bool) or not isinstance(saved_at, (int, float)):
        return False
    return -MAX_FUTURE_SKEW_SECONDS <= now - saved_at <= MAX_ANSWER_AGE_SECONDS


class SavedAnswers:
    def __init__(self, path: Path, packages: dict, advisories: dict):
        self.path = path
        self.packages = packages
        self.advisories = advisories
        self.oldest_used: float | None = None

    def _note_used(self, saved_at: float) -> None:
        if self.oldest_used is None or saved_at < self.oldest_used:
            self.oldest_used = saved_at

    def advisory_ids(self, dependency: dict) -> list[str] | None:
        entry = self.packages.get(answer_key(dependency))
        if entry is None or not _fresh(entry["at"], time.time()):
            return None
        self._note_used(entry["at"])
        return list(entry["ids"])

    def advisory(self, advisory_id: str) -> dict | None:
        entry = self.advisories.get(advisory_id)
        if entry is None or not _fresh(entry["at"], time.time()):
            return None
        self._note_used(entry["at"])
        return entry["doc"]

    def oldest_age_hours(self) -> int | None:
        if self.oldest_used is None:
            return None
        return max(0, int((time.time() - self.oldest_used) // 3600))

    def remember(self, answers: dict[str, list[str]], documents: dict[str, dict]) -> bool:
        if not answers:
            return False
        now = time.time()
        for key, ids in answers.items():
            self.packages[key] = {"ids": list(ids), "at": now}
        for advisory_id, document in documents.items():
            self.advisories[advisory_id] = {"doc": document, "at": now}
        return self._write(now)

    def _write(self, now: float) -> bool:
        live = {
            key: entry
            for key, entry in self.packages.items()
            if _fresh(entry["at"], now)
        }
        newest = sorted(live.items(), key=lambda item: item[1]["at"], reverse=True)
        kept = dict(newest[:MAX_SAVED_PACKAGES])
        referenced = {advisory for entry in kept.values() for advisory in entry["ids"]}
        documents = {
            advisory: entry
            for advisory, entry in self.advisories.items()
            if advisory in referenced and _fresh(entry["at"], now)
        }
        text = json.dumps(
            {"version": STORE_VERSION, "packages": kept, "advisories": documents},
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(text.encode("utf-8")) > MAX_STORE_BYTES:
            logger.debug("Saved OSV answers exceed the size limit; not written")
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            return bool(write_text_no_symlink(self.path, text))
        except OSError as exc:
            logger.debug("Saved OSV answers not written: %s", type(exc).__name__)
            return False


def _valid_packages(raw: object) -> dict:
    if not isinstance(raw, dict):
        return {}
    packages = {}
    for key, entry in raw.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("ids"), list):
            continue
        if all(is_valid_advisory_id(item) for item in entry["ids"]):
            packages[key] = {"ids": entry["ids"], "at": entry.get("at")}
    return packages


def _valid_documents(raw: object) -> dict:
    if not isinstance(raw, dict):
        return {}
    documents = {}
    for advisory_id, entry in raw.items():
        if not isinstance(entry, dict) or not is_valid_advisory_id(advisory_id):
            continue
        if _valid_advisory(entry.get("doc"), advisory_id):
            documents[advisory_id] = {"doc": entry["doc"], "at": entry.get("at")}
    return documents


def _read_store(path: Path) -> tuple[dict, dict]:
    try:
        text = read_text_no_symlink(path, max_bytes=MAX_STORE_BYTES)
    except (OSError, ValueError):
        return {}, {}
    if not text:
        return {}, {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}, {}
    if not isinstance(data, dict) or data.get("version") != STORE_VERSION:
        return {}, {}
    return _valid_packages(data.get("packages")), _valid_documents(data.get("advisories"))


def open_saved_answers(root: str | Path) -> SavedAnswers | None:
    try:
        path = store_path()
        if path.resolve().is_relative_to(Path(root).resolve()):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    packages, advisories = _read_store(path)
    return SavedAnswers(path, packages, advisories)
