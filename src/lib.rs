use pyo3::prelude::*;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};
use walkdir::WalkDir;
use rayon::prelude::*;
use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

mod queries;
use queries::*; 

mod types;
use types::Unreachable;

mod utils;
use utils::{ts_lang, module_name, has_parent_of_kind};

#[link(name = "tree-sitter-python")]
extern "C" { fn tree_sitter_python() -> Language; }

fn parse_file(
    root: &Path,
    file: &Path,
) -> Result<(Vec<(String, usize)>, HashSet<String>)> {
    if file.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "__init__.py")
        && std::fs::read_to_string(file)?.trim().is_empty()
    {
        return Ok((vec![], HashSet::new()));
    }

    let src = std::fs::read_to_string(file)?;
    let bytes = src.as_bytes();

    let mut parser = Parser::new();
    parser.set_language(&ts_lang())?;
    let tree = parser.parse(&src, None).context("tree-sitter parse")?;

    let lang = ts_lang();
    let q_class = Query::new(&lang, CLASS_QUERY)?;
    let q_meth = Query::new(&lang, METHOD_QUERY)?;
    let q_fun = Query::new(&lang, FUNCTION_QUERY)?;
    let q_imp = Query::new(&lang, IMPORT_QUERY)?;
    let q_call = Query::new(&lang, CALL_QUERY)?;
    let q_deco = Query::new(&lang, DECORATOR_QUERY)?;
    let q_main = Query::new(&lang, MAIN_QUERY)?;
    let q_asn = Query::new(&lang, ASSIGN_QUERY)?;
    let q_return = Query::new(&lang, "(return_statement (identifier) @ret_val)")?;

    let module = module_name(root, file);

    let mut defs = Vec::<(String, usize)>::new();
    let mut calls = HashSet::<String>::new();
    let mut aliases = HashMap::<String, String>::new();
    let mut object_types = HashMap::<String, String>::new();
    let mut method_vars = HashMap::<String, (String, String)>::new();
    let mut seen_fn = HashSet::<usize>::new();
    let mut class_methods = HashMap::<String, HashSet<String>>::new();
    let mut method_returns_self = HashMap::<String, String>::new();

    let mut cursor = QueryCursor::new();

    for m in cursor.matches(&q_imp, tree.root_node(), bytes) {
        for c in m.captures {
            let txt = c.node.utf8_text(bytes)?;
            if c.node.kind() == "import_statement" {
                for item in txt.trim_start_matches("import ").split(',') {
                    let item = item.trim();
                    if let Some(pos) = item.find(" as ") {
                        let (path, al) = item.split_at(pos);
                        aliases.insert(al[4..].trim().into(), path.trim().into());
                    } else {
                        let key = item.split('.').last().unwrap_or(item).trim();
                        aliases.insert(key.into(), item.into());
                    }
                }
            } else {
                let rest = txt.strip_prefix("from ").unwrap_or(txt);
                if let Some((pkg, items)) = rest.split_once(" import ") {
                    for itm in items.split(',') {
                        let itm = itm.trim();
                        if let Some(pos) = itm.find(" as ") {
                            let (name, al) = itm.split_at(pos);
                            aliases.insert(
                                al[4..].trim().into(),
                                format!("{}.{}", pkg.trim(), name.trim()),
                            );
                        } else {
                            aliases.insert(itm.into(), format!("{}.{}", pkg.trim(), itm.trim()));
                        }
                    }
                }
            }
        }
    }

    for m in cursor.matches(&q_class, tree.root_node(), bytes) {
        let cls_node = m.captures.iter()
            .find(|c| q_class.capture_names()[c.index as usize] == "class")
            .map(|c| c.node)
            .unwrap();
        
        let cls_name = m.captures.iter()
            .find(|c| q_class.capture_names()[c.index as usize] == "class_name")
            .map(|c| c.node.utf8_text(bytes).unwrap())
            .unwrap();

        class_methods.insert(cls_name.to_string(), HashSet::new());

        let mut mc = QueryCursor::new();
        for mm in mc.matches(&q_meth, cls_node, bytes) {
            let method_node = mm.captures.iter()
                .find(|c| q_meth.capture_names()[c.index as usize] == "method")
                .map(|c| c.node)
                .unwrap();
                
            let method_name = mm.captures.iter()
                .find(|c| q_meth.capture_names()[c.index as usize] == "method_name")
                .map(|c| c.node.utf8_text(bytes).unwrap())
                .unwrap();

            seen_fn.insert(method_node.id());
            let qualified_name = format!("{}.{}.{}", module, cls_name, method_name);
            defs.push((qualified_name, method_node.start_position().row + 1));
            
            if let Some(methods) = class_methods.get_mut(cls_name) {
                methods.insert(method_name.to_string());
            }
            
            if method_name.starts_with("__") && method_name.ends_with("__") {
                calls.insert(format!("{}.{}.{}", module, cls_name, method_name));
            }

            let mut rc = QueryCursor::new();
            for rm in rc.matches(&q_return, method_node, bytes) {
                if let Some(ret_val) = rm.captures.iter()
                    .find(|c| q_return.capture_names()[c.index as usize] == "ret_val")
                    .map(|c| c.node.utf8_text(bytes).unwrap_or(""))
                {
                    if ret_val == "self" {
                        method_returns_self.insert(
                            format!("{}.{}", cls_name, method_name),
                            cls_name.to_string()
                        );
                    }
                }
            }
        }
    }

    for m in cursor.matches(&q_asn, tree.root_node(), bytes) {
        if let (Some(var), Some(cls)) = (
            m.captures.iter()
                .find(|c| q_asn.capture_names()[c.index as usize] == "var")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| q_asn.capture_names()[c.index as usize] == "cls")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            object_types.insert(var.to_string(), cls.to_string());
        }
        
        if let (Some(var_method), Some(obj), Some(method)) = (
            m.captures.iter()
                .find(|c| q_asn.capture_names()[c.index as usize] == "var_method")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| q_asn.capture_names()[c.index as usize] == "obj")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| q_asn.capture_names()[c.index as usize] == "method")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            if let Some(cls) = object_types.get(obj) {
                method_vars.insert(var_method.to_string(), (cls.clone(), method.to_string()));
                
                calls.insert(format!("{}.{}.{}", module, cls, method));
            }
        }
    }

    let mut fc = QueryCursor::new();
    for m in fc.matches(&q_fun, tree.root_node(), bytes) {
        let func_node = m.captures.iter()
            .find(|c| q_fun.capture_names()[c.index as usize] == "function")
            .map(|c| c.node)
            .unwrap();
            
        let func_name = m.captures.iter()
            .find(|c| q_fun.capture_names()[c.index as usize] == "func_name")
            .map(|c| c.node.utf8_text(bytes).unwrap())
            .unwrap();

        if has_parent_of_kind(func_node, &["function_definition", "class_definition"]) {
            continue;
        }

        if !seen_fn.contains(&func_node.id()) {
            defs.push((format!("{}.{}", module, func_name), func_node.start_position().row + 1));
        }
    }

    for m in cursor.matches(&q_deco, tree.root_node(), bytes) {
        if let Some(deco) = m.captures.iter()
            .find(|c| q_deco.capture_names()[c.index as usize] == "decorator_name")
            .map(|c| c.node.utf8_text(bytes).ok())
            .flatten() 
        {
            calls.insert(format!("{}.{}", module, deco));
            
            if let Some(alias) = aliases.get(deco) {
                calls.insert(alias.clone());
            }
        }
        
        if let (Some(obj), Some(attr)) = (
            m.captures.iter()
                .find(|c| q_deco.capture_names()[c.index as usize] == "decorator_obj")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| q_deco.capture_names()[c.index as usize] == "decorator_attr")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            if let Some(base) = aliases.get(obj) {
                calls.insert(format!("{}.{}", base, attr));
            } else {
                calls.insert(format!("{}.{}", obj, attr));
            }
        }
    }

    fn process_chained_calls(
        node: Node, 
        bytes: &[u8], 
        object_types: &HashMap<String, String>,
        method_returns_self: &HashMap<String, String>,
        module: &str,
        calls: &mut HashSet<String>
    ) -> Option<String> {
        match node.kind() {
            "call" => {
                if let Some(func_node) = node.child_by_field_name("function") {
                    match func_node.kind() {
                        "attribute" => {
                            if let (Some(obj_node), Some(attr_node)) = (
                                func_node.child_by_field_name("object"),
                                func_node.child_by_field_name("attribute")
                            ) {
                                let method_name = attr_node.utf8_text(bytes).ok()?;
                                
                                if let Some(obj_type) = process_chained_calls(
                                    obj_node, 
                                    bytes, 
                                    object_types, 
                                    method_returns_self, 
                                    module, 
                                    calls
                                ) {
                                    let call_name = format!("{}.{}.{}", module, obj_type, method_name);
                                    calls.insert(call_name);
                                    
                                    let key = format!("{}.{}", obj_type, method_name);
                                    return method_returns_self.get(&key).cloned();
                                }
                            }
                        }
                        "identifier" => {
                            let func_name = func_node.utf8_text(bytes).ok()?;
                            calls.insert(format!("{}.{}", module, func_name));
                        }
                        _ => {}
                    }
                }
                None
            }
            "identifier" => {
                let var_name = node.utf8_text(bytes).ok()?;
                object_types.get(var_name).cloned()
            }
            _ => None
        }
    }

    for m in cursor.matches(&q_call, tree.root_node(), bytes) {
        if let Some(call_node) = m.captures.iter()
            .find(|c| c.node.kind() == "call")
            .map(|c| c.node)
        {
            process_chained_calls(
                call_node, 
                bytes, 
                &object_types, 
                &method_returns_self, 
                &module, 
                &mut calls
            );
        }
        
        if let Some(func) = m.captures.iter()
            .find(|c| q_call.capture_names()[c.index as usize] == "call_func")
            .map(|c| c.node.utf8_text(bytes).ok())
            .flatten() 
        {
            if let Some((cls, method)) = method_vars.get(func) {
                calls.insert(format!("{}.{}.{}", module, cls, method));
            } else {
                calls.insert(format!("{}.{}", module, func));
                
                if let Some(alias) = aliases.get(func) {
                    calls.insert(alias.clone());
                }
            }
        }

        if let (Some(obj), Some(method)) = (
            m.captures.iter()
                .find(|c| q_call.capture_names()[c.index as usize] == "object")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| q_call.capture_names()[c.index as usize] == "method_name")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            if let Some(cls) = object_types.get(obj) {
                calls.insert(format!("{}.{}.{}", module, cls, method));
            } else if let Some(base) = aliases.get(obj) {
                calls.insert(format!("{}.{}", base, method));
            } else {
                calls.insert(format!("{}.{}", obj, method));
            }
        }
    }

    for m in cursor.matches(&q_main, tree.root_node(), bytes) {
        let cond = m.captures.iter()
            .find(|c| q_main.capture_names()[c.index as usize] == "cond")
            .map(|c| c.node.utf8_text(bytes).unwrap_or(""))
            .unwrap_or("");
            
        if !cond.contains("__name__") || !cond.contains("__main__") {
            continue;
        }
        
        if let Some(block) = m.captures.iter()
            .find(|c| q_main.capture_names()[c.index as usize] == "block")
            .map(|c| c.node)
        {
            let mut ic = QueryCursor::new();
            for cm in ic.matches(&q_call, block, bytes) {
                if let Some(func) = cm.captures.iter()
                    .find(|c| q_call.capture_names()[c.index as usize] == "call_func")
                    .map(|c| c.node.utf8_text(bytes).ok())
                    .flatten() 
                {
                    calls.insert(format!("{}.{}", module, func));
                }

                if let (Some(obj), Some(method)) = (
                    cm.captures.iter()
                        .find(|c| q_call.capture_names()[c.index as usize] == "object")
                        .map(|c| c.node.utf8_text(bytes).ok())
                        .flatten(),
                    cm.captures.iter()
                        .find(|c| q_call.capture_names()[c.index as usize] == "method_name")
                        .map(|c| c.node.utf8_text(bytes).ok())
                        .flatten()
                ) {
                    if let Some(cls) = object_types.get(obj) {
                        calls.insert(format!("{}.{}.{}", module, cls, method));
                    } else if let Some(base) = aliases.get(obj) {
                        calls.insert(format!("{}.{}", base, method));
                    } else {
                        calls.insert(format!("{}.{}", obj, method));
                    }
                }
            }
        }
    }

    Ok((defs, calls))
}

pub fn analyze_dir(path: &str) -> Result<Vec<Unreachable>> {
    let input = PathBuf::from(path).canonicalize()?;

    let (root, files): (PathBuf, Vec<PathBuf>) = if input.is_file() {
        (input.parent().unwrap().to_path_buf(), vec![input])
    } else {
        let list = WalkDir::new(&input)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "py"))
            .map(|e| e.into_path())
            .collect();
        (input, list)
    };

    let root = Arc::new(root);

    let parsed: Vec<_> = files.par_iter()
        .filter_map(|p| {
            let r = Arc::clone(&root);
            parse_file(&r, p).ok().map(|(d, c)| (p.clone(), d, c))
        })
        .collect();

    let mut all_calls = HashSet::<String>::new();
    for (_, _, calls) in &parsed {
        all_calls.extend(calls.iter().cloned());
    }

    let mut dead = Vec::<Unreachable>::new();
    for (path, defs, _) in parsed {
        for (def, line) in defs {
            if def.ends_with(".__init__") || def.ends_with(".__str__") || 
               (def.contains(".__") && def.ends_with("__")) {
                continue;
            }
            
            if !all_calls.contains(&def) {
                dead.push(Unreachable {
                    file: path.display().to_string(),
                    name: def,
                    line,
                });
            }
        }
    }
    
    Ok(dead)
}

#[pyfunction]
fn analyze(path: String) -> PyResult<String> {
    match analyze_dir(&path) {
        Ok(result) => Ok(serde_json::to_string_pretty(&result).unwrap()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e))),
    }
}

#[pymodule]
fn _core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    Ok(())
}

/////////////////// tests ///////////////////
// This module contains unit tests for the functions in the library.
// It uses the `tempfile` crate to create temporary directories and files for testing purposes.
// The tests cover various scenarios, including parsing files, detecting function and method calls,
// handling decorators, and checking for dead code.


#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_module_name() {
        let root = Path::new("/project");
        let file = Path::new("/project/pkg/mod.py");
        assert_eq!(module_name(root, file), "pkg.mod");
    }
    
    #[test]
    fn test_empty_init_skipping() {
        let dir = tempdir().unwrap();
        let init_path = dir.path().join("__init__.py");
        fs::write(&init_path, "").unwrap();
        
        let result = parse_file(dir.path(), &init_path).unwrap();
        assert!(result.0.is_empty());
        assert!(result.1.is_empty());
    }

    #[test]
fn test_simple_function_detection() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
def used_function():
    return "Used"

def unused_function():
    return "Unused"

print(used_function())
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert_eq!(defs.len(), 2);
    
    assert!(calls.contains(&"test.used_function".to_string()));
    
    assert!(!calls.contains(&"test.unused_function".to_string()));
}

#[test]
fn test_class_method_detection() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
class TestClass:
    def __init__(self):
        self.data = "test"
    
    def used_method(self):
        return "Used method"
    
    def unused_method(self):
        return "Unused method"

obj = TestClass()
obj.used_method()
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(defs.iter().any(|(name, _)| name == "test.TestClass.__init__"));
    assert!(defs.iter().any(|(name, _)| name == "test.TestClass.used_method"));
    assert!(defs.iter().any(|(name, _)| name == "test.TestClass.unused_method"));
    
    assert!(calls.contains(&"test.TestClass.__init__".to_string()));
    assert!(calls.contains(&"test.TestClass.used_method".to_string()));
    assert!(!calls.contains(&"test.TestClass.unused_method".to_string()));
}

#[test]
fn test_analyze_dir_integration() {
    let dir = tempdir().unwrap();
    
    let file_path = dir.path().join("example.py");
    fs::write(&file_path, r#"
def used_function():
    return "used"

def unused_function():
    return "unused"

used_function()
"#).unwrap();
    
    let result = analyze_dir(dir.path().to_str().unwrap()).unwrap();
    
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "example.unused_function");
}

#[test]
fn test_import_alias_detection() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
import os.path as osp
from datetime import datetime as dt

def test_func():
    return osp.join("a", "b")

dt.now()
"#).unwrap();
    
    let (_, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"os.path.join".to_string()));
    assert!(calls.contains(&"datetime.datetime.now".to_string()));
}

#[test]
fn test_decorator_usage() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
def my_decorator(func):
    return func

@my_decorator
def decorated_func():
    pass
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"test.my_decorator".to_string()));
    assert_eq!(defs.len(), 2); 
}

#[test]
fn test_main_block_detection() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
def main():
    return "Main function"

def helper():
    return "Helper"

if __name__ == "__main__":
    main()
"#).unwrap();
    
    let (_, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"test.main".to_string()));
    assert!(!calls.contains(&"test.helper".to_string()));
}

#[test]
fn test_nonexistent_file() {
    let result = analyze_dir("/nonexistent/path");
    assert!(result.is_err());
}

#[test]
fn test_method_reference_assignment() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
class MyClass:
    def my_method(self):
        return "test"
    
    def unused_method(self):
        return "unused"

obj = MyClass()
method_ref = obj.my_method
method_ref()  # This should mark my_method as used
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"test.MyClass.my_method".to_string()));
    assert!(!calls.contains(&"test.MyClass.unused_method".to_string()));
}

#[test]
fn test_cross_module_imports() {
    let dir = tempdir().unwrap();
    
    let module_a = dir.path().join("module_a.py");
    fs::write(&module_a, r#"
def used_function():
    return "used"

def unused_function():
    return "unused"
"#).unwrap();
    
    let module_b = dir.path().join("module_b.py");
    fs::write(&module_b, r#"
from module_a import used_function

used_function()
"#).unwrap();
    
    let result = analyze_dir(dir.path().to_str().unwrap()).unwrap();
    
    assert!(result.iter().any(|u| u.name == "module_a.unused_function"));
    // used_function should NOT be in the dead code list
    assert!(!result.iter().any(|u| u.name == "module_a.used_function"));
}

#[test]
fn test_dunder_methods() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
class MyClass:
    def __init__(self):
        pass
    
    def __str__(self):
        return "MyClass"
    
    def __custom__(self):  # Non-standard dunder
        return "custom"
    
    def regular_method(self):
        return "regular"
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"test.MyClass.__init__".to_string()));
    assert!(calls.contains(&"test.MyClass.__str__".to_string()));
    assert!(calls.contains(&"test.MyClass.__custom__".to_string()));
}

#[test]
fn test_nested_functions() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
def outer_function():
    def inner_function():
        return "inner"
    
    return inner_function()

def standalone_function():
    return "standalone"

outer_function()
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert_eq!(defs.len(), 2);
    assert!(defs.iter().any(|(name, _)| name == "test.outer_function"));
    assert!(defs.iter().any(|(name, _)| name == "test.standalone_function"));
    assert!(!defs.iter().any(|(name, _)| name.contains("inner_function")));
}

#[test]
fn test_complex_imports() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
import sys, os
from datetime import datetime, timedelta as td
import numpy as np

sys.exit(0)
os.path.join('a', 'b')
datetime.now()
td(days=1)
np.array([1, 2, 3])
"#).unwrap();
    
    let (_, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"sys.exit".to_string()));
    assert!(calls.contains(&"os.path.join".to_string()));
    assert!(calls.contains(&"datetime.datetime.now".to_string()));
    assert!(calls.contains(&"datetime.timedelta".to_string()));
    assert!(calls.contains(&"numpy.array".to_string()));
}

#[test]
fn test_chained_method_calls() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
class Builder:
    def step1(self):
        return self
    
    def step2(self):
        return self
    
    def unused_method(self):
        return self

builder = Builder()
builder.step1().step2()
"#).unwrap();
    
    let (defs, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"test.Builder.step1".to_string()));
    assert!(calls.contains(&"test.Builder.step2".to_string()));
    assert!(!calls.contains(&"test.Builder.unused_method".to_string()));
}

#[test]
fn test_property_decorator() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.py");
    fs::write(&file_path, r#"
class MyClass:
    @property
    def used_property(self):
        return "used"
    
    @property
    def unused_property(self):
        return "unused"

obj = MyClass()
print(obj.used_property)
"#).unwrap();
    
    let (_, calls) = parse_file(dir.path(), &file_path).unwrap();
    
    assert!(calls.contains(&"property".to_string()) || calls.contains(&"test.property".to_string()));
}

}