use pyo3::prelude::*;
use once_cell::sync::Lazy;
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
use types::{Unreachable, UnusedImport};

mod utils;
use utils::{ts_lang, module_name, has_parent_of_kind};

#[link(name = "tree-sitter-python")]
extern "C" { fn tree_sitter_python() -> Language; }

static Q_CLASS: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), CLASS_QUERY)
        .expect("Failed to compile CLASS_QUERY")
});
static Q_METH: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), METHOD_QUERY)
        .expect("Failed to compile METHOD_QUERY")
});
static Q_FUN: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), FUNCTION_QUERY)
        .expect("Failed to compile FUNCTION_QUERY")
});
static Q_IMP: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), IMPORT_QUERY)
        .expect("Failed to compile IMPORT_QUERY")
});
static Q_CALL: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), CALL_QUERY)
        .expect("Failed to compile CALL_QUERY")
});
static Q_DECO: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), DECORATOR_QUERY)
        .expect("Failed to compile DECORATOR_QUERY")
});
static Q_MAIN: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), MAIN_QUERY)
        .expect("Failed to compile MAIN_QUERY")
});
static Q_ASN: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), ASSIGN_QUERY)
        .expect("Failed to compile ASSIGN_QUERY")
});
static Q_RETURN: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), "(return_statement (identifier) @ret_val)")
        .expect("Failed to compile return query")
});
static Q_PROP: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), PROPERTY_QUERY)
        .expect("Failed to compile PROPERTY_QUERY")
});
static Q_INST: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), INSTANTIATION_QUERY)
        .expect("Failed to compile INSTANTIATION_QUERY")
});
static Q_IDENT: Lazy<Query> = Lazy::new(|| {
    Query::new(&ts_lang(), IDENT_QUERY)
        .expect("Failed to compile IDENT_QUERY")
});

fn parse_file(
    root: &Path,
    file: &Path,
) -> Result<(Vec<(String, usize)>, HashSet<String>, Vec<(String, usize)>, HashSet<String>)> {
    if file.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "__init__.py")
        && std::fs::read_to_string(file)?.trim().is_empty()
    {
        return Ok((vec![], HashSet::new(), vec![], HashSet::new()));
    }

    let src = std::fs::read_to_string(file)?;
    let bytes = src.as_bytes();

    let mut parser = Parser::new();
    parser.set_language(&ts_lang())?;
    let tree = parser.parse(&src, None).context("tree-sitter parse")?;
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
    let mut imported_classes = HashMap::<String, String>::new(); 
    
    let mut import_defs = Vec::<(String, usize)>::new();
    let mut used_idents = HashSet::<String>::new();

    for m in cursor.matches(&Q_IMP, tree.root_node(), bytes) {
        for c in m.captures {
            let txt = c.node.utf8_text(bytes)?;
            let line_number = c.node.start_position().row + 1;
            
            if c.node.kind() == "import_statement" {
                for item in txt.trim_start_matches("import ").split(',') {
                    let item = item.trim();
                    if let Some(pos) = item.find(" as ") {
                        let (path, al) = item.split_at(pos);
                        let alias = al[4..].trim();
                        aliases.insert(alias.into(), path.trim().into());
                        import_defs.push((alias.to_string(), line_number));
                    } else {
                        let key = item.split('.').last().unwrap_or(item).trim();
                        aliases.insert(key.into(), item.into());
                        import_defs.push((key.to_string(), line_number));
                    }
                }
            } else {
                let rest = txt.strip_prefix("from ").unwrap_or(txt);
                if let Some((pkg, items)) = rest.split_once(" import ") {
                    let full_pkg = resolve_import_path(&module, pkg)?;

                    for itm in items.split(',') {
                        let itm = itm.trim();
                        if let Some(pos) = itm.find(" as ") {
                            let (name, al) = itm.split_at(pos);
                            let alias = al[4..].trim();
                            let full_name = format!("{}.{}", full_pkg, name.trim());
                            aliases.insert(alias.into(), full_name.clone());
                            imported_classes.insert(alias.into(), full_name);
                            import_defs.push((alias.to_string(), line_number));
                        } else {
                            let full_name = format!("{}.{}", full_pkg, itm);
                            aliases.insert(itm.into(), full_name.clone());
                            imported_classes.insert(itm.into(), full_name);
                            import_defs.push((itm.to_string(), line_number));
                        }
                    }
                }
            }
        }
    }

    fn resolve_import_path(current_module: &str, import_path: &str) -> Result<String> {
        if import_path.starts_with('.') {
            let mut parts: Vec<&str> = current_module.split('.').collect();
    
            // remove the module filename ⇒ operate on the *package* path
            parts.pop();
    
            let dots = import_path.chars().take_while(|&c| c == '.').count();
            if dots > parts.len() + 1 {
                return Err(anyhow::anyhow!("Relative import goes beyond top-level package"));
            }
    
            let base_parts = &parts[..parts.len() - (dots - 1)];
            let rest = import_path.trim_start_matches('.');
    
            Ok(if rest.is_empty() {
                base_parts.join(".")
            } else {
                format!("{}.{}", base_parts.join("."), rest)
            })
        } else {
            Ok(import_path.to_string())
        }
    }
    
    
    fn resolve_attribute_chain(
        attr_chain: &str,
        object_types: &HashMap<String, String>,
        imported_classes: &HashMap<String, String>,
    ) -> Option<(String, bool)> {
        if let Some(cls) = object_types.get(attr_chain) {
            let is_imported = imported_classes.contains_key(cls);
            return Some((cls.clone(), is_imported));
        }
        
        if let Some(dot_pos) = attr_chain.rfind('.') {
            let parent = &attr_chain[..dot_pos];
            if let Some((_, _)) = resolve_attribute_chain(parent, object_types, imported_classes) {
                let full_attr = attr_chain;
                if let Some(cls) = object_types.get(full_attr) {
                    let is_imported = imported_classes.contains_key(cls);
                    return Some((cls.clone(), is_imported));
                }
            }
        }
        
        None
    }
    
    fn process_chained_calls(
        node: Node, 
        bytes: &[u8], 
        object_types: &HashMap<String, String>,
        method_returns_self: &HashMap<String, String>,
        imported_classes: &HashMap<String, String>,
        module: &str,
        calls: &mut HashSet<String>,
        aliases: &HashMap<String, String>
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
                                
                                if obj_node.kind() == "call" {
                                    if let Some(class_func) = obj_node.child_by_field_name("function") {
                                        if let Ok(class_name) = class_func.utf8_text(bytes) {
                                            if let Some(full_class_path) = imported_classes.get(class_name) {
                                                let call_name = format!("{}.{}", full_class_path, method_name);
                                                calls.insert(call_name);
                                                
                                                let class_only = full_class_path.split('.').last()?;
                                                let key = format!("{}.{}", class_only, method_name);
                                                return method_returns_self.get(&key)
                                                    .map(|_| full_class_path.to_string());
                                            } else {
                                                let call_name = format!("{}.{}.{}", module, class_name, method_name);
                                                calls.insert(call_name);
                                                
                                                let key = format!("{}.{}", class_name, method_name);
                                                if method_returns_self.contains_key(&key) {
                                                    return Some(class_name.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                if let Some(obj_type) = process_chained_calls(
                                    obj_node, 
                                    bytes, 
                                    object_types, 
                                    method_returns_self,
                                    imported_classes,
                                    module, 
                                    calls,
                                    aliases
                                ) {
                                    if let Some(full_class_path) = imported_classes.get(&obj_type) {
                                        let call_name = format!("{}.{}", full_class_path, method_name);
                                        calls.insert(call_name);
                                    } else {
                                        let call_name = format!("{}.{}.{}", module, obj_type, method_name);
                                        calls.insert(call_name);
                                    }
                                    
                                    let class_name = obj_type.split('.').last().unwrap_or(&obj_type);
                                    let key = format!("{}.{}", class_name, method_name);
                                    
                                    if let Some(returned_type) = method_returns_self.get(&key) {
                                        return Some(returned_type.clone());
                                    }
                                    
                                    return None;
                                }
                            }
                        }
                        "identifier" => {
                            let func_name = func_node.utf8_text(bytes).ok()?;
                            
                            if let Some(full_path) = imported_classes.get(func_name) {
                                calls.insert(format!("{}.__init__", full_path));
                                return Some(full_path.clone());
                            } else {
                                calls.insert(format!("{}.{}", module, func_name));
                                return Some(func_name.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                None
            }
            "identifier" => {
                let var_name = node.utf8_text(bytes).ok()?;
                object_types.get(var_name).cloned()
                    .or_else(|| imported_classes.get(var_name).cloned())
            }
            _ => None
        }
    }
    

    for m in cursor.matches(&Q_CLASS, tree.root_node(), bytes) {
        let cls_node = m.captures.iter()
            .find(|c| Q_CLASS.capture_names()[c.index as usize] == "class")
            .map(|c| c.node)
            .unwrap();
        
        let cls_name = m.captures.iter()
            .find(|c| Q_CLASS.capture_names()[c.index as usize] == "class_name")
            .map(|c| c.node.utf8_text(bytes).unwrap())
            .unwrap();

        class_methods.insert(cls_name.to_string(), HashSet::new());

        let mut mc = QueryCursor::new();
        for mm in mc.matches(&Q_METH, cls_node, bytes) {
            let method_node = mm.captures.iter()
                .find(|c| Q_METH.capture_names()[c.index as usize] == "method")
                .map(|c| c.node)
                .unwrap();
                
            let method_name = mm.captures.iter()
                .find(|c| Q_METH.capture_names()[c.index as usize] == "method_name")
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
            for rm in rc.matches(&Q_RETURN, method_node, bytes) {
                if let Some(ret_val) = rm.captures.iter()
                    .find(|c| Q_RETURN.capture_names()[c.index as usize] == "ret_val")
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

    for m in cursor.matches(&Q_ASN, tree.root_node(), bytes) {
        if let (Some(left_obj), Some(left_attr), Some(right_value)) = (
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "left_obj")
                .map(|c| c.node),
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "left_attr")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "right_value")
                .map(|c| c.node)
        ) {
            if let Ok(obj_text) = left_obj.utf8_text(bytes) {
                let var_name = format!("{}.{}", obj_text, left_attr);
                
                if right_value.kind() == "call" {
                    if let Some(func_node) = right_value.child_by_field_name("function") {
                        if let Ok(class_name) = func_node.utf8_text(bytes) {
                            // resolve later lmao 
                            object_types.insert(var_name, class_name.to_string());
                            
                            if let Some(full_path) = imported_classes.get(class_name) {
                                calls.insert(format!("{}.__init__", full_path));
                            } else {
                                calls.insert(format!("{}.{}.__init__", module, class_name));
                            }
                        }
                    }
                }
            }
        }
        
        if let (Some(var), Some(value_node)) = (
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "var")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| c.node.kind() == "call")
                .map(|c| c.node)
        ) {
            if let Some(func_node) = value_node.child_by_field_name("function") {
                if let Ok(class_name) = func_node.utf8_text(bytes) {
                    object_types.insert(var.to_string(), class_name.to_string());
                    
                    if let Some(full_path) = imported_classes.get(class_name) {
                        calls.insert(format!("{}.__init__", full_path));
                    } else {
                        calls.insert(format!("{}.{}.__init__", module, class_name));
                    }
                }
            }
        }
        
        if let (Some(var), Some(value_node)) = (
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "var")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| c.node.kind() == "call")
                .map(|c| c.node)
        ) {
            if let Some(func_node) = value_node.child_by_field_name("function") {
                if let Ok(class_name) = func_node.utf8_text(bytes) {
                    if let Some(full_path) = imported_classes.get(class_name) {
                        object_types.insert(var.to_string(), full_path.split('.').last().unwrap_or(class_name).to_string());
                    } else {
                        object_types.insert(var.to_string(), class_name.to_string());
                    }
                }
            }
        }
        
        if let (Some(var), Some(cls)) = (
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "var")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "cls")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            object_types.insert(var.to_string(), cls.to_string());
        }
        
        if let (Some(var_method), Some(obj), Some(method)) = (
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "var_method")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "obj")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| Q_ASN.capture_names()[c.index as usize] == "method")
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
    for m in fc.matches(&Q_FUN, tree.root_node(), bytes) {
        let func_node = m.captures.iter()
            .find(|c| Q_FUN.capture_names()[c.index as usize] == "function")
            .map(|c| c.node)
            .unwrap();
            
        let func_name = m.captures.iter()
            .find(|c| Q_FUN.capture_names()[c.index as usize] == "func_name")
            .map(|c| c.node.utf8_text(bytes).unwrap())
            .unwrap();

        if has_parent_of_kind(func_node, &["function_definition", "class_definition"]) {
            continue;
        }

        if !seen_fn.contains(&func_node.id()) {
            defs.push((format!("{}.{}", module, func_name), func_node.start_position().row + 1));
        }
    }

    for m in cursor.matches(&Q_DECO, tree.root_node(), bytes) {
        if let Some(deco) = m.captures.iter()
            .find(|c| Q_DECO.capture_names()[c.index as usize] == "decorator_name")
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
                .find(|c| Q_DECO.capture_names()[c.index as usize] == "decorator_obj")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten(),
            m.captures.iter()
                .find(|c| Q_DECO.capture_names()[c.index as usize] == "decorator_attr")
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

    for m in cursor.matches(&Q_CALL, tree.root_node(), bytes) {
        if let Some(call_node) = m.captures.iter()
            .find(|c| c.node.kind() == "call")
            .map(|c| c.node)
        {
            process_chained_calls(
                call_node, bytes, &object_types, 
                &method_returns_self, &imported_classes,
                &module, &mut calls, &aliases 
            );
        }
        
        if let Some(attr_node) = m.captures.iter()
            .find(|c| c.node.kind() == "attribute")
            .map(|c| c.node)
        {
            if let (Some(obj_node), Some(attr)) = (
                attr_node.child_by_field_name("object"),
                attr_node.child_by_field_name("attribute")
            ) {
                if let (Ok(obj_text), Ok(attr_text)) = (
                    obj_node.utf8_text(bytes),
                    attr.utf8_text(bytes)
                ) {
                    if let Some(cls) = object_types.get(obj_text) {
                        let potential_property = format!("{}.{}.{}", module, cls, attr_text);
                        calls.insert(potential_property);
                    }
                }
            }
        }
        
        if let Some(func) = m.captures.iter()
            .find(|c| Q_CALL.capture_names()[c.index as usize] == "call_func")
            .map(|c| c.node.utf8_text(bytes).ok())
            .flatten() 
        {
            used_idents.insert(func.to_string());
            
            if let Some((cls, method)) = method_vars.get(func) {
                calls.insert(format!("{}.{}.{}", module, cls, method));
            } else {
                calls.insert(format!("{}.{}", module, func));
                
                if let Some(alias) = aliases.get(func) {
                    calls.insert(alias.clone());
                }
            }
        }

        if let (Some(obj_node), Some(method)) = (
            m.captures.iter()
                .find(|c| Q_CALL.capture_names()[c.index as usize] == "object")
                .map(|c| c.node),
            m.captures.iter()
                .find(|c| Q_CALL.capture_names()[c.index as usize] == "method_name")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            if let Ok(obj_text) = obj_node.utf8_text(bytes) {
                used_idents.insert(obj_text.to_string());
                
                if let Some((cls, is_imported)) = resolve_attribute_chain(obj_text, &object_types, &imported_classes) {
                    if is_imported {
                        if let Some(full_path) = imported_classes.get(&cls) {
                            calls.insert(format!("{}.{}", full_path, method));
                        }
                    } else {
                        calls.insert(format!("{}.{}.{}", module, cls, method));
                    }
                } else if let Some(base) = aliases.get(obj_text) {
                    calls.insert(format!("{}.{}", base, method));
                } else {
                    // fallback
                    calls.insert(format!("{}.{}", obj_text, method));
                }
            }
        }
    }

    for m in cursor.matches(&Q_MAIN, tree.root_node(), bytes) {
        let cond = m.captures.iter()
            .find(|c| Q_MAIN.capture_names()[c.index as usize] == "cond")
            .map(|c| c.node.utf8_text(bytes).unwrap_or(""))
            .unwrap_or("");
            
        if !cond.contains("__name__") || !cond.contains("__main__") {
            continue;
        }
        
        if let Some(block) = m.captures.iter()
            .find(|c| Q_MAIN.capture_names()[c.index as usize] == "block")
            .map(|c| c.node)
        {
            let mut ic = QueryCursor::new();
            for cm in ic.matches(&Q_CALL, block, bytes) {
                if let Some(func) = cm.captures.iter()
                    .find(|c| Q_CALL.capture_names()[c.index as usize] == "call_func")
                    .map(|c| c.node.utf8_text(bytes).ok())
                    .flatten() 
                {
                    used_idents.insert(func.to_string());
                    calls.insert(format!("{}.{}", module, func));
                }

                if let (Some(obj), Some(method)) = (
                    cm.captures.iter()
                        .find(|c| Q_CALL.capture_names()[c.index as usize] == "object")
                        .map(|c| c.node.utf8_text(bytes).ok())
                        .flatten(),
                    cm.captures.iter()
                        .find(|c| Q_CALL.capture_names()[c.index as usize] == "method_name")
                        .map(|c| c.node.utf8_text(bytes).ok())
                        .flatten()
                ) {
                    used_idents.insert(obj.to_string());
                    
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

    // property access
    for m in cursor.matches(&Q_PROP, tree.root_node(), bytes) {
        if let (Some(obj_node), Some(prop)) = (
            m.captures.iter()
                .find(|c| Q_PROP.capture_names()[c.index as usize] == "prop_object")
                .map(|c| c.node),
            m.captures.iter()
                .find(|c| Q_PROP.capture_names()[c.index as usize] == "prop_name")
                .map(|c| c.node.utf8_text(bytes).ok())
                .flatten()
        ) {
            if let Ok(obj_text) = obj_node.utf8_text(bytes) {
                used_idents.insert(obj_text.to_string());
                
                if let Some((cls, is_imported)) = resolve_attribute_chain(obj_text, &object_types, &imported_classes) {
                    if is_imported {
                        if let Some(full_path) = imported_classes.get(&cls) {
                            calls.insert(format!("{}.{}", full_path, prop));
                        }
                    } else {
                        calls.insert(format!("{}.{}.{}", module, cls, prop));
                    }
                }
            }
        }
    }

    for m in cursor.matches(&Q_IDENT, tree.root_node(), bytes) {
        for capture in m.captures {
            let ident_node = capture.node;
            
            // Skip identifiers in import statements
            let mut parent = ident_node.parent();
            let mut in_import = false;
            
            while let Some(p) = parent {
                let kind = p.kind();
                if kind == "import_statement" || kind == "import_from_statement" {
                    in_import = true;
                    break;
                }
                parent = p.parent();
            }
            
            if !in_import {
                if let Ok(ident) = ident_node.utf8_text(bytes) {
                    used_idents.insert(ident.to_string());
                }
            }
        }
    }

    Ok((defs, calls, import_defs, used_idents))
}

fn collapsed(pkg_call: &str) -> String {
    let mut pieces: Vec<&str> = pkg_call.split('.').collect();
    if pieces.len() > 2 {
        pieces.remove(pieces.len() - 2);
    }
    pieces.join(".")
}

pub fn analyze_dir(path: &str) -> Result<(Vec<Unreachable>, Vec<UnusedImport>)> {
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
            parse_file(&r, p).ok().map(|(d, c, i, u)| (p.clone(), d, c, i, u))
        })
        .collect();

    let mut all_calls = HashSet::<String>::new();
    for (_, _, calls, _, _) in &parsed {
        for c in calls {
            all_calls.insert(c.clone());
            all_calls.insert(collapsed(c));
        }
    }

    let mut dead = Vec::<Unreachable>::new();
    let mut unused_imports = Vec::<UnusedImport>::new();
    
    for (path, defs, _, imports, used_idents) in parsed {
        for (def, line) in defs {
            if def.ends_with(".__init__") || def.ends_with(".__str__")
                || (def.contains(".__") && def.ends_with("__"))
            {
                continue;
            }
        
            let def_alt = collapsed(&def);
            if !all_calls.contains(&def) && !all_calls.contains(&def_alt) {
                dead.push(Unreachable {
                    file: path.display().to_string(),
                    name: def,
                    line,
                });
            }
        }
        
        for (import_name, line) in &imports {
            if import_name == "*" {
                continue;
            }
            
            let is_used = used_idents.contains(import_name) || 
                          used_idents.iter().any(|ident| ident.starts_with(&format!("{}.", import_name)));
            
            if !is_used {
                unused_imports.push(UnusedImport {
                    file: path.display().to_string(),
                    name: import_name.clone(),
                    line: *line,
                });
            }
        }
    }
    
    Ok((dead, unused_imports))
}

#[pyfunction]
fn analyze(path: String) -> PyResult<String> {
    match analyze_dir(&path) {
        Ok((dead, unused_imports)) => {
            let result = serde_json::json!({
                "unused_functions": dead,
                "unused_imports": unused_imports
            });
            Ok(serde_json::to_string_pretty(&result).unwrap())
        },
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
        assert!(result.2.is_empty());
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
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (dead, _) = analyze_dir(dir.path().to_str().unwrap()).unwrap();
        
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].name, "example.unused_function");
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
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
method_ref()
"#).unwrap();
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (dead, _) = analyze_dir(dir.path().to_str().unwrap()).unwrap();
        
        assert!(dead.iter().any(|u| u.name == "module_a.unused_function"));
        // used_function should NOT be in the dead code list
        assert!(!dead.iter().any(|u| u.name == "module_a.used_function"));
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
    
    def __custom__(self):
        return "custom"
    
    def regular_method(self):
        return "regular"
"#).unwrap();
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
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
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
        assert!(calls.contains(&"property".to_string()) || calls.contains(&"test.property".to_string()));
    }

    #[test]
    fn test_star_imports() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.py");
        fs::write(&file_path, r#"
from math import *

sqrt(16)
"#).unwrap();
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        assert!(calls.contains(&"test.sqrt".to_string()) || calls.contains(&"math.sqrt".to_string()));
    }

    #[test]
    fn test_multiple_decorators() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.py");
        fs::write(&file_path, r#"
def decorator1(func):
    return func

def decorator2(func):
    return func

@decorator1
@decorator2
def decorated_func():
    pass
"#).unwrap();
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
        assert!(calls.contains(&"test.decorator1".to_string()));
        assert!(calls.contains(&"test.decorator2".to_string()));
    }

    #[test]
    fn test_comprehensions_with_calls() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.py");
        fs::write(&file_path, r#"
def process(x):
    return x * 2

def unused(x):
    return x

result = [process(x) for x in range(10)]
"#).unwrap();
        
        let (_, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
        assert!(calls.contains(&"test.process".to_string()));
        assert!(!calls.contains(&"test.unused".to_string()));
    }

    #[test]
    fn test_context_managers() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.py");
        fs::write(&file_path, r#"
class MyContext:
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

with MyContext() as ctx:
    pass
"#).unwrap();
        
        let (defs, calls, _) = parse_file(dir.path(), &file_path).unwrap();
        
        assert!(calls.contains(&"test.MyContext.__enter__".to_string()));
        assert!(calls.contains(&"test.MyContext.__exit__".to_string()));
    }
}