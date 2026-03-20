//! Fast file discovery using the `ignore` crate (same engine as ripgrep).
//! Replaces analyzer.py's `_get_python_files()` / `_get_ts_files()` / `_get_go_files()`.

use ignore::WalkBuilder;
use pyo3::prelude::*;
use std::path::PathBuf;

/// Walk a directory tree and return matching source files, respecting .gitignore.
///
/// Args:
///     root: Root directory to scan.
///     extensions: File extensions to include (e.g. ["py", "ts", "go"]).
///     exclude_dirs: Directory names to skip (e.g. ["node_modules", ".venv", "__pycache__"]).
///
/// Returns:
///     List of absolute file paths.
#[pyfunction]
#[pyo3(signature = (root, extensions, exclude_dirs = None))]
pub fn discover_files(
    root: &str,
    extensions: Vec<String>,
    exclude_dirs: Option<Vec<String>>,
) -> PyResult<Vec<String>> {
    let exclude = exclude_dirs.unwrap_or_default();
    let ext_set: std::collections::HashSet<String> = extensions.into_iter().collect();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .build();

    let mut files = Vec::new();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Skip excluded directories
        if entry.file_type().map_or(false, |ft| ft.is_dir()) {
            if let Some(name) = entry.file_name().to_str() {
                if exclude.iter().any(|ex| ex == name) {
                    continue;
                }
            }
        }

        if !entry.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }

        let path: PathBuf = entry.into_path();
        // Check extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext_set.contains(ext) {
                // Skip excluded dir components
                let dominated = path.components().any(|c| {
                    if let std::path::Component::Normal(seg) = c {
                        seg.to_str()
                            .map_or(false, |s| exclude.iter().any(|ex| ex == s))
                    } else {
                        false
                    }
                });
                if !dominated {
                    if let Some(s) = path.to_str() {
                        files.push(s.to_string());
                    }
                }
            }
        }
    }

    files.sort();
    Ok(files)
}
