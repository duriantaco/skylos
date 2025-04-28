use pyo3::prelude::*;
use tree_sitter::{Language, Parser, QueryCursor, Query};
use walkdir::WalkDir;
use rayon::prelude::*;
use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Serialize, Debug, Clone)]
pub struct Unreachable {
    pub file: String,
    
    pub name: String,
    
    pub line: usize
}

#[link(name = "tree-sitter-python")]
extern "C" {
    fn tree_sitter_python() -> Language;
}

fn ts_lang() -> Language {
    unsafe { tree_sitter_python() }
}

fn module_name(root: &Path, file: &Path) -> String {
    match file.strip_prefix(root) {
        Ok(rel) => rel.with_extension("")
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join("."),
        Err(_) => {
            file.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string()
        }
    }
}

fn resolve_call(raw: &str, alias: &HashMap<String, String>, module: &str) -> String {
    let parts: Vec<_> = raw.split('.').collect();
    
    if parts.is_empty() { 
        return raw.to_string(); 
    }
    
    if let Some(base) = alias.get(parts[0]) {
        if parts.len() == 1 { 
            base.clone() 
        } else { 
            format!("{}.{}", base, parts[1..].join(".")) 
        }
    } else if parts.len() == 1 {
        format!("{}.{}", module, parts[0])
    } else {
        raw.to_string()
    }
}

const FUNCTION_QUERY: &str = r#"
(function_definition
  name: (identifier) @func_name) @function
"#;

const IMPORT_QUERY: &str = r#"
(import_statement) @import
(import_from_statement) @import_from
"#;

const CALL_QUERY: &str = r#"
(call function: (_) @call_func)
"#;

fn parse_file(root: &Path, file: &Path) -> Result<(Vec<(String, usize)>, Vec<String>)> {
    let src = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let src_bytes = src.as_bytes();
    
    let mut parser = Parser::new();
    parser.set_language(&ts_lang())
        .map_err(|e| anyhow!("Failed to set language: {}", e))?;
    
    let tree = parser.parse(&src, None)
        .context("Failed to parse Python source")?;
    
    let language = ts_lang();
    
    let function_query = Query::new(&language, FUNCTION_QUERY)
        .map_err(|e| anyhow!("Invalid function query: {}", e))?;
    let import_query = Query::new(&language, IMPORT_QUERY)
        .map_err(|e| anyhow!("Invalid import query: {}", e))?;
    let call_query = Query::new(&language, CALL_QUERY)
        .map_err(|e| anyhow!("Invalid call query: {}", e))?;
    
    let mut cursor = QueryCursor::new();
    let root_node = tree.root_node();
    
    let mut defs = Vec::<(String, usize)>::new();
    for match_ in cursor.matches(&function_query, root_node, src_bytes) {
        for capture in match_.captures {
            if function_query.capture_names()[capture.index as usize] == "func_name" {
                let name = capture.node.utf8_text(src_bytes)?;
                let line = capture.node.start_position().row + 1;
                defs.push((name.to_string(), line));
            }
        }
    }
    
    cursor = QueryCursor::new();
    
    let mut alias = HashMap::<String, String>::new();
    for match_ in cursor.matches(&import_query, root_node, src_bytes) {
        for capture in match_.captures {
            let node = capture.node;
            let text = node.utf8_text(src_bytes)?;
            
            if node.kind() == "import_statement" {
                for item in text.trim_start_matches("import ").split(',') {
                    let part = item.trim();
                    if let Some(idx) = part.find(" as ") {
                        let (path_part, alias_part) = part.split_at(idx);
                        alias.insert(
                            alias_part[4..].trim().to_string(), 
                            path_part.trim().to_string()
                        );
                    } else {
                        let key = part.split('.').last().unwrap_or(part).trim().to_string();
                        alias.insert(key, part.to_string());
                    }
                }
            } else if node.kind() == "import_from_statement" {
                if let Some(rest) = text.strip_prefix("from ") {
                    if let Some((module_part, import_part)) = rest.split_once(" import ") {
                        let module_path = module_part.trim();
                        for itm in import_part.split(',') {
                            let itm = itm.trim();
                            if let Some(idx) = itm.find(" as ") {
                                let (name, a) = itm.split_at(idx);
                                alias.insert(
                                    a[4..].trim().to_string(), 
                                    format!("{}.{}", module_path, name.trim())
                                );
                            } else {
                                alias.insert(
                                    itm.to_string(), 
                                    format!("{}.{}", module_path, itm)
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    
    cursor = QueryCursor::new();
    
    let mut call_raw = Vec::<String>::new();
    for match_ in cursor.matches(&call_query, root_node, src_bytes) {
        for capture in match_.captures {
            if call_query.capture_names()[capture.index as usize] == "call_func" {
                let name = capture.node.utf8_text(src_bytes)?;
                call_raw.push(name.to_string());
            }
        }
    }
    
    let module = module_name(root, file);
    
    let q_defs = defs.into_iter()
        .map(|(n, l)| (format!("{}.{}", module, n), l))
        .collect();
    
    let calls = call_raw.into_iter()
        .map(|c| resolve_call(&c, &alias, &module))
        .collect();
    
    Ok((q_defs, calls))
}

pub fn analyze_dir(dir: &str) -> Result<Vec<Unreachable>> {
    let root = match PathBuf::from(dir).canonicalize() {
        Ok(p) => p,
        Err(_) => PathBuf::from(dir),
    };
    
    let files: Vec<_> = WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.path().extension()
                .map_or(false, |ext| ext == "py")
        })
        .map(|e| e.into_path())
        .collect();
    
    if files.is_empty() {
        return Ok(Vec::new());
    }
    
    let root = Arc::new(root);
    
    let parsed = files.par_iter()
        .map(|p| {
            let root_ref = Arc::clone(&root);
            parse_file(&root_ref, p)
                .map(|r| (p.clone(), r.0, r.1))
                .with_context(|| format!("Failed to parse file: {}", p.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    
    let mut called = HashSet::<String>::new();
    for (_, _, cs) in &parsed {
        called.extend(cs.iter().cloned());
    }
    
    let mut dead = Vec::<Unreachable>::new();
    for (path, defs, _) in parsed {
        for (d, line) in defs {
            if !called.contains(&d) {
                dead.push(Unreachable {
                    file: path.display().to_string(),
                    name: d,
                    line,
                });
            }
        }
    }
    
    Ok(dead)
}

#[pyfunction]
fn analyze(path: String) -> PyResult<String> {
    let res = analyze_dir(&path)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Analysis failed: {}", e)
        ))?;
    
    serde_json::to_string_pretty(&res)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("JSON serialization failed: {}", e)
        ))
}

#[pymodule]
fn _core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    Ok(())
}