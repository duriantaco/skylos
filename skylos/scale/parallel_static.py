from concurrent.futures import ProcessPoolExecutor, as_completed


def _worker(file_path, mod, extra_visitors):
    from skylos.analyzer import proc_file

    out = proc_file(file_path, mod, extra_visitors=extra_visitors)
    return str(file_path), out


def run_proc_file_parallel(
    files,
    modmap,
    extra_visitors=None,
    jobs=0,
    progress_callback=None,
    custom_rules_data=None,
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

            from skylos.analyzer import proc_file

            out = proc_file(f, modmap[f], extra_visitors=extra_visitors)
            outs.append(out)

        return outs

    if jobs <= 0:
        jobs = max(1, (os.cpu_count() or 4) - 1)

    pending = []
    for f in files:
        pending.append((f, modmap[f]))

    results = {}

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
                out = None

            results[file_str] = out

            done += 1
            if progress_callback:
                progress_callback(done, total, f)

    ordered = []
    for f in files:
        ordered.append(results.get(str(f)))

    return ordered
