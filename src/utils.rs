use std::path::Path;
use tree_sitter::{Language, Node};

#[link(name = "tree-sitter-python", kind = "static")]
extern "C" {
    fn tree_sitter_python() -> Language;
}

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

    if parts.last().map_or(false, |&p| p == "__init__") {
        parts.pop(); 
        if parts.is_empty() { 
            if let Some(pkg_name) = file.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) {
                // Avoid adding the root project directory name if file is like /project/__init__.py
                // This logic might need further refinement based on exact desired behavior for root __init__.py
                if file.parent() != Some(root) { 
                   parts.push(pkg_name);
                }
            }
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