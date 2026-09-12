from __future__ import annotations

import copy
import json

from skylos.core.review_context import (
    LLM_REVIEW_CONTEXT_SCHEMA,
    build_llm_review_context,
    review_context_hash_for_category,
    review_context_is_valid,
)
from skylos.llm.prompts import analysis_prompt_revision


def _build_context(root, **overrides):
    source = root / "src" / "app.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        overrides.pop("source_text", "def handler():\n    return 1\n"),
        encoding="utf-8",
    )
    prompt_revision = analysis_prompt_revision("review")
    values = {
        "mode": "agent_llm_only",
        "config": {"exclude": ["vendor"], "complexity": 10},
        "exclude_folders": [".git", "vendor"],
        "requested_changed_files": None,
        "effective_files": [source],
        "repo_context_map": {source: "- review_score=30"},
        "force_full_file_paths": {source},
        "definitions": {},
        "scan_kind": "directory",
        "complete_target": True,
        "model": "gpt-4.1",
        "provider": "openai",
        "base_url": "https://llm.example.test/v1",
        "min_confidence": "low",
        "prompt_revision": prompt_revision,
        "enable_security": True,
        "enable_quality": True,
        "temperature": 0.0,
        "max_tokens": 4_096,
        "strict_validation": False,
        "stream": True,
        "smart_filter": True,
        "full_file_review": False,
        "parallel": True,
        "max_workers": 4,
        "max_chunk_tokens": 1_000,
        "batch_functions": True,
        "batch_size": 10,
        "complexity_threshold": 5,
        "agent_route": "full",
    }
    values.update(overrides)
    return build_llm_review_context(root, root, **values)


def test_llm_review_context_is_valid_and_category_scoped(tmp_path):
    context = _build_context(tmp_path)

    assert context["schema"] == LLM_REVIEW_CONTEXT_SCHEMA
    assert review_context_is_valid(context)
    assert review_context_hash_for_category(context, "QUALITY")
    assert review_context_hash_for_category(context, "SECURITY")
    assert review_context_hash_for_category(context, "DEAD_CODE") is None
    assert "llm.example.test" not in json.dumps(context)


def test_llm_review_context_binds_runtime_config_and_selection(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    base = _build_context(root)
    source = root / "src" / "app.py"
    changed = root / "src" / "changed.py"
    changed.write_text("value = 1\n", encoding="utf-8")

    variants = [
        _build_context(root, model="gpt-4.2"),
        _build_context(root, provider="anthropic"),
        _build_context(root, min_confidence="high"),
        _build_context(root, temperature=0.2),
        _build_context(root, max_tokens=8_192),
        _build_context(root, strict_validation=True),
        _build_context(root, stream=False),
        _build_context(root, config={"exclude": ["vendor"], "complexity": 11}),
        _build_context(root, exclude_folders=[".git", "generated"]),
        _build_context(root, requested_changed_files=[changed]),
        _build_context(root, effective_files=[source, changed]),
        _build_context(
            root,
            repo_context_map={source: "- review_score=90"},
        ),
        _build_context(root, force_full_file_paths=set()),
        _build_context(root, smart_filter=False),
        _build_context(root, max_chunk_tokens=2_000),
        _build_context(
            root,
            definitions={
                "shared.helper": {
                    "name": "helper",
                    "file": root / "src" / "app.py",
                    "type": "function",
                }
            },
        ),
        _build_context(root, source_text="def handler():\n    return 2\n"),
    ]

    assert all(review_context_is_valid(item) for item in variants)
    assert all(item["context_hash"] != base["context_hash"] for item in variants)


def test_llm_review_context_distinguishes_llm_only_and_hybrid_modes(tmp_path):
    llm_only = _build_context(tmp_path, mode="agent_llm_only")
    hybrid = _build_context(tmp_path, mode="agent_hybrid_llm")

    assert review_context_is_valid(llm_only)
    assert review_context_is_valid(hybrid)
    assert hybrid["context_hash"] != llm_only["context_hash"]
    assert review_context_hash_for_category(hybrid, "QUALITY")


def test_llm_review_context_is_checkout_independent(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()

    first = _build_context(
        first_root,
        definitions={
            "app.handler": {
                "name": "handler",
                "file": first_root / "src" / "app.py",
                "type": "function",
            }
        },
    )
    second = _build_context(
        second_root,
        definitions={
            "app.handler": {
                "name": "handler",
                "file": second_root / "src" / "app.py",
                "type": "function",
            }
        },
    )

    assert first == second


def test_llm_review_context_fails_open_for_incomplete_or_tampered_inputs(tmp_path):
    context = _build_context(tmp_path, provider=None)
    assert context == {"schema": LLM_REVIEW_CONTEXT_SCHEMA, "complete": False}
    assert not review_context_is_valid(context)
    assert review_context_hash_for_category(context, "QUALITY") is None

    valid = _build_context(tmp_path)
    tampered = copy.deepcopy(valid)
    tampered["analyzer"]["model"] = "different-model"
    assert not review_context_is_valid(tampered)
    assert review_context_hash_for_category(tampered, "QUALITY") is None


def test_analysis_prompt_revision_tracks_effective_template_content(tmp_path):
    template = tmp_path / "review.md"
    template.write_text("Check tenant isolation.\n", encoding="utf-8")
    first = analysis_prompt_revision(
        "review",
        templates={"review": str(template)},
        template_root=tmp_path,
    )
    template.write_text("Check authorization boundaries.\n", encoding="utf-8")
    second = analysis_prompt_revision(
        "review",
        templates={"review": str(template)},
        template_root=tmp_path,
    )

    assert first and first.startswith("sha256:")
    assert second and second.startswith("sha256:")
    assert first != second
    assert analysis_prompt_revision("unknown") is None
