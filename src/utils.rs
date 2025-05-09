// src/utils.rs
use std::path::Path;
use tree_sitter::{Language, Node};

#[link(name = "tree-sitter-python")]
extern "C" { fn tree_sitter_python() -> Language; }

pub fn ts_lang() -> Language {
    unsafe { tree_sitter_python() }
}

pub fn module_name(root: &Path, file: &Path) -> String {
    let path_no_ext = file
        .strip_prefix(root)
        .unwrap_or(file)
        .with_extension("");

    let mut parts: Vec<&str> = path_no_ext
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    let init_at_root = matches!(parts.last(), Some(&"__init__"));
    if init_at_root {
        parts.pop();
    }

    if parts.is_empty() {
        // eg.  /project/pkg/__init__.py  ---->  "pkg"
        if let Some(pkg) = file.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) {
            parts.push(pkg);
        }
    }

    parts.join(".")
}

pub fn has_parent_of_kind(mut node: Node, kinds: &[&str]) -> bool {
    while let Some(p) = node.parent() {
        if kinds.contains(&p.kind()) {
            return true;
        }
        node = p;
    }
    false
}