# skylos-fast: Rust accelerator for Skylos
# This module is the PyO3 extension — the actual implementation
# lives in rust/src/ and gets compiled by maturin.
#
# Usage from skylos:
#   try:
#       from skylos_fast import discover_files
#   except ImportError:
#       # pure Python fallback
#       ...

from skylos_fast.skylos_fast import (
    discover_files,
    detect_clone_pairs,
    compute_similarity,
    analyze_coupling,
    find_cycles,
)

__all__ = [
    "discover_files",
    "detect_clone_pairs",
    "compute_similarity",
    "analyze_coupling",
    "find_cycles",
]
