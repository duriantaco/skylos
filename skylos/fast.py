try:
    from skylos_fast import (
        discover_files as fast_discover_files,
        detect_clone_pairs as fast_clone_pairs,
        compute_similarity as fast_similarity,
        analyze_coupling as fast_coupling,
        find_cycles as fast_cycles,
    )

    FAST_AVAILABLE = True
except ImportError:
    fast_discover_files = None
    fast_clone_pairs = None
    fast_similarity = None
    fast_coupling = None
    fast_cycles = None

    FAST_AVAILABLE = False


try:
    from skylos_fast import grep_batch as fast_grep_batch

    FAST_GREP_AVAILABLE = True
except ImportError:
    fast_grep_batch = None

    FAST_GREP_AVAILABLE = False
