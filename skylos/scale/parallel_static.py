from concurrent.futures import ProcessPoolExecutor, as_completed
import logging


logger = logging.getLogger("Skylos")


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
):
    import os

    if os.getenv("PYTEST_CURRENT_TEST"):
        jobs = 1

    if jobs <= 0:
        jobs = max(1, (os.cpu_count() or 4) - 1)
    if len(files) <= 1:
        jobs = 1

    if jobs <= 1:
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
            )
            outs.append(out)

        return outs

    pending = []
    for f in files:
        pending.append((f, modmap[f]))

    results = {}

    with ProcessPoolExecutor(max_workers=jobs) as ex:
        fut_to_file = {}
        for f, mod in pending:
            full_scan = changed_files is None or str(f) in changed_files
            fut = ex.submit(
                _worker,
                f,
                mod,
                extra_visitors,
                full_scan,
                collect_clone_fragments,
                clone_cfg,
                collect_architecture_metrics,
                enable_quality_rules,
                enable_danger_rules,
                config_file,
            )
            fut_to_file[fut] = f

        total = len(pending)
        done = 0

        for fut in as_completed(fut_to_file):
            f = fut_to_file[fut]

            try:
                file_str, out = fut.result()
            except Exception:
                file_str = str(f)
                logger.warning(
                    "Parallel static worker failed for %s; retrying in parent process",
                    file_str,
                    exc_info=True,
                )
                try:
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
                    )
                except Exception:
                    logger.error(
                        "Parent-process static retry failed for %s",
                        file_str,
                        exc_info=True,
                    )
                    out = None

            results[file_str] = out

            done += 1
            if progress_callback:
                progress_callback(done, total, f)

    ordered = []
    for f in files:
        ordered.append(results.get(str(f)))

    return ordered
