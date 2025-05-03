// src/utils.rs
use std::path::Path;
use tree_sitter::{Language, Node};

#[link(name = "tree-sitter-python")]
extern "C" { fn tree_sitter_python() -> Language; }

pub fn ts_lang() -> Language { 
    unsafe { tree_sitter_python() } 
}

pub fn module_name(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .with_extension("")
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join(".")
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