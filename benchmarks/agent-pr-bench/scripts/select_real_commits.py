#!/usr/bin/env python3
"""Select real agent-authored commits from public GitHub repositories.

This script is run once to build ``corpus/real_commits.json``. Its output is
checked in and pinned by SHA; the benchmark run itself never re-selects, so the
corpus does not drift when GitHub search results change.

Selection procedure (all read-only GitHub API calls through ``gh api``):

1. Repository frame: for each language, the repository-search results for
   ``language:<L> stars:<range> pushed:>=<window start> archived:false
   fork:false`` sorted by stars, first ``--repo-pages`` pages of 100.
   Repositories larger than ``--max-repo-kb`` are dropped (clone/scan cost).
2. Commit frame: every commit in each repository's default branch within the
   fixed date window (first ``--commit-pages`` pages of 100).
3. Agent attribution: a commit is agent-authored when its message carries an
   agent trailer or its author login is an agent bot (see AGENT_SIGNATURES).
4. Change filter: exactly one parent, and between ``--min-add`` and
   ``--max-add`` added lines in Python/TypeScript/JavaScript source files,
   touching at most ``--max-files`` files in total.
5. Sampling: candidates are ranked by sha256(repo + sha) (a reproducible
   pseudo-random order), at most one commit per repository, filled round-robin
   across (agent, language) buckets up to ``--target``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CODE_EXTENSIONS = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

# Ordered: first match wins. Each entry: (agent, kind, pattern).
AGENT_SIGNATURES = [
    ("claude", "trailer", re.compile(r"^co-authored-by:\s*claude\b.*$", re.I | re.M)),
    ("claude", "trailer", re.compile(r"^.*generated with \[?claude code.*$", re.I | re.M)),
    ("copilot", "author", "copilot-swe-agent[bot]"),
    ("copilot", "trailer", re.compile(r"^co-authored-by:\s*copilot\s*<.*$", re.I | re.M)),
    ("cursor", "trailer", re.compile(r"^co-authored-by:.*cursoragent@cursor\.com.*$", re.I | re.M)),
    ("devin", "author", "devin-ai-integration[bot]"),
    ("devin", "trailer", re.compile(r"^co-authored-by:.*devin-ai-integration.*$", re.I | re.M)),
    ("codex", "trailer", re.compile(r"^co-authored-by:\s*codex\b.*$", re.I | re.M)),
]

VENDORED = re.compile(
    r"(^|/)(node_modules|vendor|third_party|dist|build|\.next|generated|__generated__)/"
    r"|\.min\.js$|\.d\.ts$|(^|/)package-lock\.json$"
)


def gh_api(path: str, params: dict | None = None, *, retries: int = 6) -> object:
    cmd = ["gh", "api", "-X", "GET", path]
    for key, value in (params or {}).items():
        cmd += ["-f", f"{key}={value}"]
    delay = 20.0
    for attempt in range(retries):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            return json.loads(proc.stdout or "null")
        err = proc.stderr + proc.stdout
        if "rate limit" in err.lower() and attempt + 1 < retries:
            print(f"  rate limited on {path}; sleeping {delay:.0f}s", file=sys.stderr)
            time.sleep(delay)
            delay *= 2
            continue
        if "HTTP 404" in err or "HTTP 409" in err or "HTTP 451" in err:
            return None
        raise RuntimeError(f"gh api {path} failed: {err.strip()[:400]}")
    raise RuntimeError(f"gh api {path}: retries exhausted")


def attribute(commit: dict) -> tuple[str, str] | None:
    message = commit["commit"]["message"]
    login = ((commit.get("author") or {}).get("login")) or ""
    for agent, kind, pattern in AGENT_SIGNATURES:
        if kind == "author":
            if login == pattern:
                return agent, f"author login {login}"
        else:
            match = pattern.search(message)
            if match:
                return agent, match.group(0).strip()[:200]
    return None


def rank_key(repo: str, sha: str) -> str:
    return hashlib.sha256(f"{repo}@{sha}".encode()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", default="2026-06-01")
    ap.add_argument("--until", default="2026-09-20")
    ap.add_argument("--stars", default="300..60000")
    ap.add_argument("--languages", default="Python,TypeScript")
    ap.add_argument("--repo-pages", type=int, default=3)
    ap.add_argument("--commit-pages", type=int, default=2)
    ap.add_argument("--max-repo-kb", type=int, default=150_000)
    ap.add_argument("--min-add", type=int, default=15)
    ap.add_argument("--max-add", type=int, default=1200)
    ap.add_argument("--max-files", type=int, default=40)
    ap.add_argument("--target", type=int, default=36)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--pool-out", type=Path, help="Optional: write the full candidate pool")
    args = ap.parse_args()

    repos: dict[str, dict] = {}
    for lang in args.languages.split(","):
        query = (
            f"language:{lang} stars:{args.stars} pushed:>={args.since} "
            "archived:false fork:false"
        )
        for page in range(1, args.repo_pages + 1):
            data = gh_api(
                "search/repositories",
                {"q": query, "sort": "stars", "order": "desc", "per_page": 100, "page": page},
            )
            for item in (data or {}).get("items", []):
                if item["size"] > args.max_repo_kb:
                    continue
                repos.setdefault(
                    item["full_name"],
                    {
                        "language": lang.lower(),
                        "stars": item["stargazers_count"],
                        "default_branch": item["default_branch"],
                    },
                )
            time.sleep(3)  # search API: 30 requests/minute
    print(f"repository frame: {len(repos)} repos", file=sys.stderr)

    attributed = []
    for i, (full_name, meta) in enumerate(sorted(repos.items())):
        for page in range(1, args.commit_pages + 1):
            commits = gh_api(
                f"repos/{full_name}/commits",
                {
                    "sha": meta["default_branch"],
                    "since": f"{args.since}T00:00:00Z",
                    "until": f"{args.until}T23:59:59Z",
                    "per_page": 100,
                    "page": page,
                },
            )
            if not commits:
                break
            for commit in commits:
                hit = attribute(commit)
                if hit:
                    attributed.append((full_name, commit["sha"], hit[0], hit[1]))
            if len(commits) < 100:
                break
        if (i + 1) % 50 == 0:
            print(f"  scanned {i + 1}/{len(repos)} repos, {len(attributed)} agent commits", file=sys.stderr)
    print(f"agent-attributed commits: {len(attributed)}", file=sys.stderr)

    # Rank first so detail lookups stop early once each repo has a candidate.
    attributed.sort(key=lambda row: rank_key(row[0], row[1]))
    pool = []
    seen_repo: set[str] = set()
    for full_name, sha, agent, evidence in attributed:
        if full_name in seen_repo:
            continue
        detail = gh_api(f"repos/{full_name}/commits/{sha}")
        if not detail or len(detail.get("parents", [])) != 1:
            continue
        files = detail.get("files") or []
        if not files or len(files) > args.max_files:
            continue
        code_files = []
        langs: dict[str, int] = {}
        for f in files:
            path = f["filename"]
            ext = Path(path).suffix.lower()
            if ext not in CODE_EXTENSIONS or VENDORED.search(path) or f["status"] == "removed":
                continue
            code_files.append(
                {"path": path, "status": f["status"], "additions": f["additions"], "deletions": f["deletions"]}
            )
            lang = CODE_EXTENSIONS[ext]
            langs[lang] = langs.get(lang, 0) + f["additions"]
        added = sum(cf["additions"] for cf in code_files)
        if not code_files or not (args.min_add <= added <= args.max_add):
            continue
        primary = max(langs, key=langs.get)
        if primary == "javascript":
            primary = "typescript"  # JS/TS share one bucket and one ruleset family
        pool.append(
            {
                "repo": full_name,
                "sha": sha,
                "parent": detail["parents"][0]["sha"],
                "agent": agent,
                "attribution_evidence": evidence,
                "language": primary,
                "repo_stars_at_selection": repos[full_name]["stars"],
                "commit_date": detail["commit"]["committer"]["date"],
                "subject": detail["commit"]["message"].splitlines()[0][:160],
                "url": detail["html_url"],
                "code_files": code_files,
                "code_additions": added,
                "code_deletions": sum(cf["deletions"] for cf in code_files),
                "rank": rank_key(full_name, sha),
            }
        )
        seen_repo.add(full_name)

    buckets: dict[tuple[str, str], list[dict]] = {}
    for cand in pool:
        buckets.setdefault((cand["agent"], cand["language"]), []).append(cand)
    order = sorted(buckets)
    selected: list[dict] = []
    while len(selected) < args.target and any(buckets[k] for k in order):
        for key in order:
            if buckets[key] and len(selected) < args.target:
                selected.append(buckets[key].pop(0))

    selected.sort(key=lambda c: (c["language"], c["agent"], c["repo"]))
    for n, cand in enumerate(selected, 1):
        cand["id"] = f"real-{n:02d}"
    payload = {
        "schema": "agent-pr-bench/real-commits@1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "selection": {
            **{k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items() if k not in {"out", "pool_out"}},
            "repository_frame_size": len(repos),
            "agent_attributed_commits": len(attributed),
            "eligible_pool_one_per_repo": len(pool),
            "pool_by_bucket": {f"{a}/{l}": sum(1 for c in pool if (c['agent'], c['language']) == (a, l)) for a, l in order},
            "signatures": [
                {"agent": a, "kind": k, "pattern": p if isinstance(p, str) else p.pattern}
                for a, k, p in AGENT_SIGNATURES
            ],
        },
        "commits": selected,
    }
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    if args.pool_out:
        args.pool_out.write_text(json.dumps(pool, indent=2) + "\n")
    print(f"selected {len(selected)} commits -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
