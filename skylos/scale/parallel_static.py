from __future__ import annotations
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


def _worker(file_path, mod, extra_visitors):
    from skylos.analyzer import proc_file

    return str(file_path), proc_file(file_path, mod, extra_visitors)


def run_proc_file_parallel(
    files, modmap, extra_visitors=None, jobs=0, cache=None, progress_callback=None
):
    import os

    if os.getenv("PYTEST_CURRENT_TEST"):
        jobs = 1

    if jobs <= 1:
        outs = []
        total = len(files)
        for i, f in enumerate(files, 1):
            if progress_callback:
                progress_callback(i, total or 1, f)

            if cache:
                cached = cache.get(f)
                if cached is not None:
                    outs.append(cached)
                    continue

            from skylos.analyzer import proc_file

            out = proc_file(f, modmap[f], extra_visitors=extra_visitors)

            if cache:
                cache.put(f, out)

            outs.append(out)
        return outs

    if jobs <= 0:
        jobs = max(1, (os.cpu_count() or 4) - 1)

    results = {}
    pending = []  # (Path, mod)
    cache_ok = True

    for f in files:
        if cache and cache_ok:
            cached = cache.get(f)
            if cached is not None:
                results[str(f)] = cached
                continue
        pending.append((f, modmap[f]))

    if pending:
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            fut_to_file = {}
            for f, mod in pending:
                fut = ex.submit(_worker, f, mod, extra_visitors)
                fut_to_file[fut] = f

            total = len(pending)
            done = 0

            for fut in as_completed(fut_to_file):
                f = fut_to_file[fut]

                try:
                    file_str, out = fut.result()
                except Exception:
                    file_str = str(f)
                    out = (
                        [],  # defs
                        [],  # refs
                        set(),  # dyn
                        set(),  # exports
                        {},  # test_flags
                        {},  # framework_flags
                        [],  # q_finds
                        [],  # d_finds
                        [],  # pro_finds
                        None,  # pattern_tracker
                        None,  # empty_file_finding
                        {"ignore": []},  # cfg
                    )

                results[file_str] = out

                if cache and cache_ok:
                    try:
                        cache.put(Path(file_str), out)
                    except Exception:
                        cache_ok = False

                done += 1
                if progress_callback:
                    progress_callback(done, total, f)

    ordered = []
    for f in files:
        ordered.append(results.get(str(f)))
    return ordered
