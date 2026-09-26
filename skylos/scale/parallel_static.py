from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
import logging


logger = logging.getLogger("Skylos")


WORKER_CRASH_MESSAGE = "parser crashed on this file; skipped"


class WorkerCrash:
    """Parent-side marker for a file whose analysis killed a worker process."""

    __slots__ = ("file",)

    def __init__(self, file):
        self.file = file

    def __repr__(self):
        return f"WorkerCrash({self.file!r})"


def _run_pool(files, modmap, changed_files, jobs, worker_fn, proc_kwargs, progress):
    """Run files in a fresh process pool.

    Returns (results, broken): results maps str(path) -> proc_file output for
    every file that finished (or whose ordinary Python exception was retried
    in the parent); broken lists files whose futures failed because the pool
    died, in submission order. Those must not be re-run in the parent.
    """
    results = {}
    broken = []
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        fut_to_file = {}
        for f in files:
            full_scan = changed_files is None or str(f) in changed_files
            try:
                fut = ex.submit(
                    worker_fn,
                    f,
                    modmap[f],
                    proc_kwargs["extra_visitors"],
                    full_scan,
                    proc_kwargs["collect_clone_fragments"],
                    proc_kwargs["clone_cfg"],
                    proc_kwargs["collect_architecture_metrics"],
                    proc_kwargs["enable_quality_rules"],
                    proc_kwargs["enable_danger_rules"],
                    proc_kwargs["config_file"],
                    proc_kwargs["project_root"],
                )
            except BrokenProcessPool:
                broken.append(f)
                continue
            fut_to_file[fut] = f

        for fut in as_completed(fut_to_file):
            f = fut_to_file[fut]
            file_str = str(f)
            try:
                file_str, out = fut.result()
            except BrokenProcessPool:
                broken.append(f)
                continue
            except Exception:
                logger.warning(
                    "Parallel static worker failed for %s; retrying in parent process",
                    file_str,
                    exc_info=True,
                )
                out = _retry_in_parent(f, modmap, changed_files, proc_kwargs)
            results[file_str] = out
            progress(f)

    order = {id(f): i for i, f in enumerate(files)}
    broken.sort(key=lambda f: order.get(id(f), 0))
    return results, broken


def _retry_in_parent(f, modmap, changed_files, proc_kwargs):
    try:
        from skylos.analyzer import proc_file

        full_scan = changed_files is None or str(f) in changed_files
        return proc_file(f, modmap[f], full_scan=full_scan, **proc_kwargs)
    except Exception:
        logger.error(
            "Parent-process static retry failed for %s", str(f), exc_info=True
        )
        return None


def _worker(
    file_path,
    mod,
    extra_visitors,
    full_scan=True,
    collect_clone_fragments=False,
    clone_cfg=None,
    collect_architecture_metrics=False,
    enable_quality_rules=True,
    enable_danger_rules=True,
    config_file=None,
    project_root=None,
):
    from skylos.analyzer import proc_file

    out = proc_file(
        file_path,
        mod,
        extra_visitors=extra_visitors,
        full_scan=full_scan,
        collect_clone_fragments=collect_clone_fragments,
        clone_cfg=clone_cfg,
        collect_architecture_metrics=collect_architecture_metrics,
        enable_quality_rules=enable_quality_rules,
        enable_danger_rules=enable_danger_rules,
        config_file=config_file,
        project_root=project_root,
    )
    return str(file_path), out


def run_proc_file_parallel(
    files,
    modmap,
    extra_visitors=None,
    jobs=0,
    progress_callback=None,
    custom_rules_data=None,
    changed_files=None,
    collect_clone_fragments=False,
    clone_cfg=None,
    collect_architecture_metrics=False,
    enable_quality_rules=True,
    enable_danger_rules=True,
    config_file=None,
    project_root=None,
    _worker_fn=None,
):
    import os

    if os.getenv("PYTEST_CURRENT_TEST") and _worker_fn is None:
        jobs = 1

    if jobs <= 0:
        jobs = max(1, (os.cpu_count() or 4) - 1)
    if len(files) <= 1:
        jobs = 1

    if jobs <= 1:
        return _run_proc_files_serial(
            files,
            modmap,
            extra_visitors=extra_visitors,
            progress_callback=progress_callback,
            changed_files=changed_files,
            collect_clone_fragments=collect_clone_fragments,
            clone_cfg=clone_cfg,
            collect_architecture_metrics=collect_architecture_metrics,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
            config_file=config_file,
            project_root=project_root,
        )

    if any(str(f).endswith(".go") for f in files):
        return _run_mixed_files_with_serial_go(
            files,
            modmap,
            extra_visitors=extra_visitors,
            jobs=jobs,
            progress_callback=progress_callback,
            custom_rules_data=custom_rules_data,
            changed_files=changed_files,
            collect_clone_fragments=collect_clone_fragments,
            clone_cfg=clone_cfg,
            collect_architecture_metrics=collect_architecture_metrics,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
            config_file=config_file,
            project_root=project_root,
            _worker_fn=_worker_fn,
        )

    proc_kwargs = {
        "extra_visitors": extra_visitors,
        "collect_clone_fragments": collect_clone_fragments,
        "clone_cfg": clone_cfg,
        "collect_architecture_metrics": collect_architecture_metrics,
        "enable_quality_rules": enable_quality_rules,
        "enable_danger_rules": enable_danger_rules,
        "config_file": config_file,
        "project_root": project_root,
    }
    worker_fn = _worker_fn or _worker
    total = len(files)
    done = 0

    def _progress(f):
        nonlocal done
        done += 1
        if progress_callback:
            progress_callback(done, total, f)

    results, suspects = _run_pool(
        files, modmap, changed_files, jobs, worker_fn, proc_kwargs, _progress
    )

    # A native crash (e.g. SIGSEGV in a tree-sitter grammar) kills a worker and
    # breaks the whole pool: every unfinished future fails with
    # BrokenProcessPool, so the culprit cannot be identified from the parent.
    # Never retry those files in the parent process (the crash would take the
    # whole scan down). Re-run them in fresh pools, in chunks of `jobs`, and
    # isolate any chunk that breaks again file-by-file in single-worker pools.
    while suspects:
        chunk, suspects = suspects[:jobs], suspects[jobs:]
        chunk_results, broken = _run_pool(
            chunk, modmap, changed_files, jobs, worker_fn, proc_kwargs, _progress
        )
        results.update(chunk_results)
        for f in broken:
            solo_results, solo_broken = _run_pool(
                [f], modmap, changed_files, 1, worker_fn, proc_kwargs, _progress
            )
            results.update(solo_results)
            if solo_broken:
                logger.error(
                    "Static analysis worker crashed on %s; file skipped", str(f)
                )
                results[str(f)] = WorkerCrash(str(f))
                _progress(f)

    ordered = []
    for f in files:
        ordered.append(results.get(str(f)))

    return ordered


def _run_mixed_files_with_serial_go(
    files,
    modmap,
    extra_visitors=None,
    jobs=0,
    progress_callback=None,
    custom_rules_data=None,
    changed_files=None,
    collect_clone_fragments=False,
    clone_cfg=None,
    collect_architecture_metrics=False,
    enable_quality_rules=True,
    enable_danger_rules=True,
    config_file=None,
    project_root=None,
    _worker_fn=None,
):
    go_files = []
    other_files = []
    for f in files:
        if str(f).endswith(".go"):
            go_files.append(f)
        else:
            other_files.append(f)

    completed = 0
    total = len(files)

    def child_progress(_done, _total, file_path):
        nonlocal completed
        completed += 1
        if progress_callback:
            progress_callback(completed, total or 1, file_path)

    results = {}
    if other_files:
        other_outs = run_proc_file_parallel(
            other_files,
            modmap,
            extra_visitors=extra_visitors,
            jobs=jobs,
            progress_callback=child_progress,
            custom_rules_data=custom_rules_data,
            changed_files=changed_files,
            collect_clone_fragments=collect_clone_fragments,
            clone_cfg=clone_cfg,
            collect_architecture_metrics=collect_architecture_metrics,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
            config_file=config_file,
            project_root=project_root,
            _worker_fn=_worker_fn,
        )
        for f, out in zip(other_files, other_outs):
            results[str(f)] = out

    if go_files:
        go_outs = _run_proc_files_serial(
            go_files,
            modmap,
            extra_visitors=extra_visitors,
            progress_callback=child_progress,
            changed_files=changed_files,
            collect_clone_fragments=collect_clone_fragments,
            clone_cfg=clone_cfg,
            collect_architecture_metrics=collect_architecture_metrics,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
            config_file=config_file,
            project_root=project_root,
        )
        for f, out in zip(go_files, go_outs):
            results[str(f)] = out

    return [results.get(str(f)) for f in files]


def _run_proc_files_serial(
    files,
    modmap,
    extra_visitors=None,
    progress_callback=None,
    changed_files=None,
    collect_clone_fragments=False,
    clone_cfg=None,
    collect_architecture_metrics=False,
    enable_quality_rules=True,
    enable_danger_rules=True,
    config_file=None,
    project_root=None,
):
    outs = []
    total = len(files)
    for i, f in enumerate(files, 1):
        if progress_callback:
            progress_callback(i, total or 1, f)

        from skylos.analyzer import proc_file

        full_scan = changed_files is None or str(f) in changed_files
        out = proc_file(
            f,
            modmap[f],
            extra_visitors=extra_visitors,
            full_scan=full_scan,
            collect_clone_fragments=collect_clone_fragments,
            clone_cfg=clone_cfg,
            collect_architecture_metrics=collect_architecture_metrics,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
            config_file=config_file,
            project_root=project_root,
        )
        outs.append(out)

    return outs
