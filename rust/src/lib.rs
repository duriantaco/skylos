use pyo3::prelude::*;

mod file_discovery;
mod clones;
mod visitor; // future: AST visitor acceleration (stub — not yet wired)
mod coupling;
mod cycles;

/// Rust accelerator for Skylos — drop-in replacement for hot paths.
/// Install via `pip install skylos[fast]`.
#[pymodule]
fn skylos_fast(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(file_discovery::discover_files, m)?)?;
    m.add_function(wrap_pyfunction!(clones::detect_clone_pairs, m)?)?;
    m.add_function(wrap_pyfunction!(clones::compute_similarity, m)?)?;
    m.add_function(wrap_pyfunction!(coupling::analyze_coupling, m)?)?;
    m.add_function(wrap_pyfunction!(cycles::find_cycles, m)?)?;
    Ok(())
}
