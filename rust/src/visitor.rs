//! Fast definition + reference collection from Python AST.
//! Uses rustpython-parser to parse Python source and walk the AST natively in Rust.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};

/// Parse a Python file and collect all defined names and referenced names.
///
/// Args:
///     source: Python source code as a string.
///     file_path: Path of the file (for location info).
///
/// Returns:
///     Dict with:
///         "definitions": list of {"name", "line", "col", "kind"} dicts
///         "references": list of referenced name strings
///         "imports": list of {"name", "module", "alias"} dicts
#[pyfunction]
pub fn collect_definitions_and_refs(
    py: Python<'_>,
    source: &str,
    file_path: &str,
) -> PyResult<PyObject> {
    let mut definitions: Vec<HashMap<String, PyObject>> = Vec::new();
    let mut references: HashSet<String> = HashSet::new();
    let mut imports: Vec<HashMap<String, PyObject>> = Vec::new();

    let parsed = rustpython_parser::parse(source, rustpython_parser::Mode::Module, file_path);

    match parsed {
        Ok(ast) => {
            walk_ast(py, &ast, &mut definitions, &mut references, &mut imports)?;
        }
        Err(_) => {
            // Parse failure — return empty, Python fallback handles it
        }
    }

    let result = PyDict::new_bound(py);

    let py_defs: Vec<PyObject> = definitions
        .into_iter()
        .map(|d| {
            let dict = PyDict::new_bound(py);
            for (k, v) in d {
                dict.set_item(k, v).unwrap();
            }
            dict.into()
        })
        .collect();
    result.set_item("definitions", py_defs)?;

    let py_refs: Vec<&str> = references.iter().map(|s| s.as_str()).collect();
    result.set_item("references", py_refs)?;

    let py_imports: Vec<PyObject> = imports
        .into_iter()
        .map(|d| {
            let dict = PyDict::new_bound(py);
            for (k, v) in d {
                dict.set_item(k, v).unwrap();
            }
            dict.into()
        })
        .collect();
    result.set_item("imports", py_imports)?;

    Ok(result.into())
}

fn walk_ast(
    _py: Python<'_>,
    _ast: &rustpython_parser::ast::Mod,
    _definitions: &mut Vec<HashMap<String, PyObject>>,
    _references: &mut HashSet<String>,
    _imports: &mut Vec<HashMap<String, PyObject>>,
) -> PyResult<()> {
    // TODO: Phase 1 implementation — walk Module.body statements
    // 1. FunctionDef / AsyncFunctionDef → definitions
    // 2. ClassDef → definitions
    // 3. Import / ImportFrom → imports
    // 4. Name (Load ctx) → references
    // 5. Attribute → dotted name references
    // 6. Call → resolve target references
    Ok(())
}
