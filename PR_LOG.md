# Skylos PR Log

PRs submitted to open source repos using findings from `skylos agent verify`.

---

## 1. psf/black — MERGED

- **PR**: [#5041](https://github.com/psf/black/pull/5041)
- **Status**: MERGED (2026-03-12)
- **Merged by**: JelleZijlstra
- **Branch**: `duriantaco:remove-dead-code` → `psf:main`
- **Lines changed**: 0 additions, 24 deletions
- **Files**: 3
- **Findings removed**:
  - `matches_grammar()` in `parsing.py` — utility function with zero callers
  - `lib2to3_unparse()` in `parsing.py` — utility function with zero callers
  - `is_function_or_class()` in `nodes.py` — function with zero callers
  - `Deprecated` in `mode.py` — warning class never raised or referenced
- **Skylos config**: `skylos agent verify --provider anthropic --max-verify 100`
- **Notes**: Reviewer asked to remove CHANGES.md entry, added `ci: skip news` label

---

## 2. psf/black — PENDING

- **PR**: [#5052](https://github.com/psf/black/pull/5052)
- **Status**: PENDING
- **Branch**: `duriantaco:remove-dead-code`
- **Lines changed**: 0 additions, 36 deletions
- **Files**: 3
- **Findings removed**:
  - `ISTERMINAL()`, `ISNONTERMINAL()`, `ISEOF()` in `token.py` — unused utility functions
  - `dump_nfa()`, `dump_dfa()` in `pgen.py` — unused debug methods (commented out at call sites)
  - `was_checked` in `pytree.py` — unused class attribute (note: `was_changed` nearby is still used)
- **Skylos config**: `skylos agent verify --provider anthropic --max-verify 100`

---

## 3. spotify/luigi — PENDING

- **PR**: Submitted (2026-03-15)
- **Status**: PENDING
- **Branch**: `duriantaco:remove-dead-code` → `spotify:master`
- **Lines changed**: 0 additions, ~13 deletions
- **Files**: 4
- **Findings removed**:
  - `varkw`, `kwonlyargs`, `kwonlydefaults`, `ann` in `scheduler.py` — unused unpacked variables from `inspect.getfullargspec()`
  - `_server_already_running()` in `process.py` — unused private function
  - `CURRENT_SOURCE_VERSION` in `db_task_history.py` — unused class constant
  - `OutputPipeProcessWrapper.writeLine()` in `format.py` — unused method
- **Skylos config**: `skylos agent verify --provider anthropic --max-verify 250`
- **Notes**: CI lint failed initially due to extra blank line in process.py, fixed with follow-up commit

---

## 4. celery/celery — PENDING

- **PR**: Not yet submitted (2026-03-15)
- **Status**: CHANGES READY
- **Branch**: `duriantaco:remove-dead-code`
- **Lines changed**: 0 additions, 123 deletions
- **Files**: 9
- **Findings removed**:
  - `reclassmethod()` in `local.py` — unused utility function
  - `load_extension_classes()` in `utils/imports.py` — unused utility function
  - `active_thread_count()` in `apps/worker.py` — unused utility function
  - `_start_worker_process()` in `contrib/testing/worker.py` — unused context manager
  - `_local_timezone` in `utils/time.py` — variable never assigned or read
  - `_process_aware` in `utils/log.py` — variable never read
  - `force_label` in `bin/graph.py` — class attribute never used
  - `_prev_outs` in `contrib/rdb.py` — class attribute never assigned or read
  - 7 unused `AsynPool` methods in `concurrency/asynpool.py`:
    `_process_cleanup_queues`, `_stop_task_handler`, `_process_register_queues`,
    `_setup_queues`, `_set_result_sentinel`, `_help_stuff_finish_args`, `_help_stuff_finish`
- **Skylos config**: `skylos agent verify --provider anthropic --max-verify 250`
- **Skylos stats**: 300 findings → 56 verified true positives, 193 false positives, 15 selected for PR

---

## 5. celery/celery — PENDING

- **PR**: [#10201](https://github.com/celery/celery/pull/10201)
- **Status**: PENDING (2026-03-15)
- **Branch**: `duriantaco:remove-dead-code-v2` → `celery:main`
- **Lines changed**: 0 additions, ~75 deletions
- **Files**: 8
- **Findings removed**:
  - `reclassmethod()` in `local.py` — unused utility function
  - `load_extension_classes()` deprecated as wrapper for `load_extension_class_names()`
  - `active_thread_count()` in `apps/worker.py` — unused utility function
  - `_start_worker_process()` in `contrib/testing/worker.py` — unused context manager
  - `_local_timezone` in `utils/time.py` — variable never assigned or read
  - `_process_aware` in `utils/log.py` — variable never read
  - `force_label` in `bin/graph.py` — class attribute never used
  - `_prev_outs` in `contrib/rdb.py` — class attribute never assigned or read
- **Notes**: Initial PR removed asynpool.py parent class overrides (broke worker shutdown) — reverted. Copilot review caught: (1) should use CDeprecationWarning not DeprecationWarning, (2) missing try/except in load_extension_classes wrapper. Both fixed.

---

## 6. Flagsmith/flagsmith — MERGED

- **PR**: [#6953](https://github.com/Flagsmith/flagsmith/pull/6953)
- **Status**: MERGED (2026-03-16)
- **Merged by**: matthewelwell
- **Branch**: `duriantaco:remove-dead-code` → `Flagsmith:main`
- **Lines changed**: 0 additions, 56 deletions
- **Files**: 10
- **Findings removed**:
  - `WebhookSendError` in `webhooks/exceptions.py` — exception never raised or caught (file deleted)
  - `WebhookURLSerializer` in `webhooks/serializers.py` — serializer never used in any view
  - `ViewResponseDoesNotHaveStatus` in `sse/exceptions.py` — exception never raised or caught
  - `ImproperlyConfiguredError` in `app/exceptions.py` — exception never raised (file deleted)
  - `IdentitySerializerFull` in `environments/identities/serializers.py` — serializer never used
  - `BaseDetailedPermissionsSerializer` in `permissions/serializers.py` — serializer never imported
  - `UTMDataModel` in `users/models.py` — pydantic model never instantiated
  - `DispatchResponse` in `custom_auth/mfa/trench/responses.py` — response class never returned
  - `OAuthError` in `custom_auth/oauth/exceptions.py` — exception never raised
  - `get_next_segment_priority` in `features/models.py` — function never called
- **Skylos config**: `skylos . --json` on `api/` directory

---

## 7. py-pdf/pypdf — MERGED

- **PR**: [#3685](https://github.com/py-pdf/pypdf/pull/3685)
- **Status**: MERGED (2026-03-16)
- **Merged by**: stefan6419846
- **Branch**: `duriantaco:remove-dead-code` → `py-pdf:main`
- **Lines changed**: 0 additions, 12 deletions
- **Files**: 2
- **Findings removed**:
  - `FieldFlag` in `constants.py` — IntFlag class (Table 8.70) never used or imported
  - `_win_encoding_rev` in `_codecs/__init__.py` — reverse encoding dict never referenced
  - `_mac_encoding_rev` in `_codecs/__init__.py` — reverse encoding dict never referenced
  - `_symbol_encoding_rev` in `_codecs/__init__.py` — reverse encoding dict never referenced
  - `_zapfding_encoding_rev` in `_codecs/__init__.py` — reverse encoding dict never referenced
- **Notes**: `_pdfdoc_encoding_rev` kept — used in `generic/_base.py` and exported in `__all__`

---

## 8. mitmproxy/mitmproxy — MERGED

- **PR**: [#8136](https://github.com/mitmproxy/mitmproxy/pull/8136)
- **Status**: MERGED (2026-03-18)
- **Merged by**: mhils
- **Branch**: `duriantaco:remove-dead-code` → `mitmproxy:main`
- **Lines changed**: 0 additions, 42 deletions
- **Files**: 5
- **Findings removed**:
  - `setbit()`/`getbit()` in `utils/bits.py` — entire file deleted, zero callers
  - `SearchError` in `tools/console/flowview.py` — exception never raised or caught
  - `colorize_url()` in `tools/console/common.py` — zero callers
  - `fcol()` in `tools/console/options.py` — zero callers
  - `view_orders` in `tools/console/consoleaddons.py` — never referenced
- **Skylos config**: `skylos . --json`
- **Notes**: Reverted `save_settings()` removal — added in 2017 but never wired into `export()`, flagged in PR for maintainer input

---

## 9. networkx/networkx — MERGED

- **PR**: [#8572](https://github.com/networkx/networkx/pull/8572)
- **Status**: MERGED (2026-03-18)
- **Merged by**: rossbar
- **Branch**: `duriantaco:remove-dead-code` → `networkx:main`
- **Lines changed**: 1 addition, 31 deletions
- **Files**: 5
- **Findings removed**:
  - `_edges_cross_nodes()` in `algorithms/tree/branchings.py` — unused private function
  - Unused imports in `algorithms/connectivity/kcutsets.py`, `algorithms/dominating.py`, `algorithms/tree/operations.py`, `generators/nonisomorphic_trees.py`
- **Skylos config**: `skylos . --json`
- **Notes**: `spectral_projection` restored per maintainer feedback — dschult opened #8575 to review the full threshold module separately

---

## Summary

| Repo | PR | Status | Files | Lines Removed | Findings |
|------|----|--------|-------|---------------|----------|
| psf/black | #5041 | MERGED | 3 | -24 | 4 |
| psf/black | #5052 | PENDING | 3 | -36 | 6 |
| spotify/luigi | TBD | PENDING | 4 | -13 | 4 |
| celery/celery | #10201 | PENDING | 8 | -75 | 8 |
| Flagsmith/flagsmith | #6953 | MERGED | 10 | -56 | 10 |
| py-pdf/pypdf | #3685 | MERGED | 2 | -12 | 5 |
| mitmproxy/mitmproxy | #8136 | MERGED | 5 | -42 | 5 |
| networkx/networkx | #8572 | MERGED | 5 | -31 | 5 |
| **Total** | | | **40** | **-289** | **47** |
