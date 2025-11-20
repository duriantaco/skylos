use crate::utils::LineIndex;
use rustpython_ast::{self as ast, Expr, Stmt};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Definition {
    pub name: String,
    pub full_name: String,
    pub simple_name: String,
    pub def_type: String,
    pub file: PathBuf,
    pub line: usize,
    pub confidence: u8,
    pub references: usize,
    pub is_exported: bool,
    pub in_init: bool,
    pub base_classes: Vec<String>,
}

impl Definition {
    /// Apply confidence penalties based on naming patterns and context
    pub fn apply_penalties(&mut self) {
        let mut confidence: i16 = 100;

        // Private names (starts with _ but not __)
        if self.simple_name.starts_with('_') && !self.simple_name.starts_with("__") {
            confidence -= 30;
        }

        // Dunder/magic methods - zero confidence
        if self.simple_name.starts_with("__") && self.simple_name.ends_with("__") {
            confidence = 0;
        }

        // In __init__.py penalty
        if self.in_init && (self.def_type == "function" || self.def_type == "class") {
            confidence -= 20;
        }

        self.confidence = confidence.max(0) as u8;
    }
}

pub struct SkylosVisitor<'a> {
    pub definitions: Vec<Definition>,
    pub references: Vec<(String, PathBuf)>,
    pub exports: Vec<String>,
    pub dynamic_imports: Vec<String>,
    pub file_path: PathBuf,
    pub module_name: String,
    pub current_scope: Vec<String>,
    pub class_stack: Vec<String>,
    pub line_index: &'a LineIndex,
}

impl<'a> SkylosVisitor<'a> {
    pub fn new(file_path: PathBuf, module_name: String, line_index: &'a LineIndex) -> Self {
        Self {
            definitions: Vec::new(),
            references: Vec::new(),
            exports: Vec::new(),
            dynamic_imports: Vec::new(),
            file_path,
            module_name,
            current_scope: Vec::new(),
            class_stack: Vec::new(),
            line_index,
        }
    }

    fn add_def(&mut self, name: String, def_type: &str, line: usize) {
        self.add_def_with_bases(name, def_type, line, Vec::new());
    }

    fn add_def_with_bases(
        &mut self,
        name: String,
        def_type: &str,
        line: usize,
        base_classes: Vec<String>,
    ) {
        let simple_name = name.split('.').last().unwrap_or(&name).to_string();
        let in_init = self.file_path.ends_with("__init__.py");

        let definition = Definition {
            name: name.clone(),
            full_name: name,
            simple_name,
            def_type: def_type.to_string(),
            file: self.file_path.clone(),
            line,
            confidence: 100,
            references: 0,
            is_exported: false,
            in_init,
            base_classes,
        };

        // Note: Penalties are applied by the analyzer, not here
        self.definitions.push(definition);
    }

    pub fn add_ref(&mut self, name: String) {
        self.references.push((name, self.file_path.clone()));
    }

    fn get_qualified_name(&self, name: &str) -> String {
        let mut parts = Vec::new();
        if !self.module_name.is_empty() {
            parts.push(self.module_name.clone());
        }
        parts.extend(self.class_stack.clone());
        parts.push(name.to_string());
        parts.join(".")
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::FunctionDef(node) => {
                let name = &node.name;
                let qualified_name = self.get_qualified_name(name.as_str());
                let line = self.line_index.line_index(node.range.start());

                // Determine if this is a method or function based on class context
                let def_type = if !self.class_stack.is_empty() {
                    "method"
                } else {
                    "function"
                };

                self.add_def(qualified_name, def_type, line);

                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            Stmt::ClassDef(node) => {
                let name = &node.name;
                let qualified_name = self.get_qualified_name(name.as_str());
                let line = self.line_index.line_index(node.range.start());

                // Extract base class names
                let mut base_classes = Vec::new();
                for base in &node.bases {
                    match base {
                        Expr::Name(base_name) => {
                            base_classes.push(base_name.id.to_string());
                        }
                        Expr::Attribute(attr) => {
                            base_classes.push(attr.attr.to_string());
                        }
                        _ => {}
                    }
                }

                self.add_def_with_bases(qualified_name, "class", line, base_classes.clone());

                // Add references for base classes with qualified names
                for base in &node.bases {
                    // Visit the expression to add references
                    self.visit_expr(base);

                    // Also add a module-qualified reference for simple base class names
                    // This ensures that "BaseClass" gets counted as a reference to "module.BaseClass"
                    match base {
                        Expr::Name(base_name) => {
                            if !self.module_name.is_empty() {
                                let qualified_base =
                                    format!("{}.{}", self.module_name, base_name.id);
                                self.add_ref(qualified_base);
                            }
                        }
                        _ => {}
                    }
                }

                self.class_stack.push(name.to_string());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                self.class_stack.pop();
            }
            Stmt::Import(node) => {
                for alias in &node.names {
                    let asname = alias.asname.as_ref().unwrap_or(&alias.name);
                    let line = self.line_index.line_index(node.range.start());
                    self.add_def(asname.to_string(), "import", line);
                }
            }
            Stmt::ImportFrom(node) => {
                let line = self.line_index.line_index(node.range.start());

                if let Some(module) = &node.module {
                    for alias in &node.names {
                        let asname = alias.asname.as_ref().unwrap_or(&alias.name);

                        // Track the import with qualified name
                        let import_name = if asname == &alias.name {
                            format!("{}.{}", module, alias.name)
                        } else {
                            asname.to_string()
                        };

                        self.add_def(import_name, "import", line);
                    }
                } else {
                    // Relative import without module
                    for alias in &node.names {
                        let asname = alias.asname.as_ref().unwrap_or(&alias.name);
                        self.add_def(asname.to_string(), "import", line);
                    }
                }
            }
            Stmt::Assign(node) => {
                // Check for __all__ = [...] pattern to detect exports
                if let Some(Expr::Name(target)) = node.targets.first() {
                    if target.id.as_str() == "__all__" {
                        // Extract export names from list
                        if let Expr::List(list) = &*node.value {
                            for elt in &list.elts {
                                if let Expr::Constant(constant) = elt {
                                    if let ast::Constant::Str(s) = &constant.value {
                                        self.exports.push(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                // Visit the assignment value for references
                self.visit_expr(&node.value);
            }
            Stmt::Expr(node) => {
                self.visit_expr(&node.value);
            }
            _ => {} // Other statement types not yet handled
        }
    }

    pub fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Name(node) => {
                if node.ctx.is_load() {
                    self.add_ref(node.id.to_string());
                }
            }
            Expr::Call(node) => {
                self.visit_expr(&node.func);
                for arg in &node.args {
                    self.visit_expr(arg);
                }
            }
            Expr::Attribute(node) => {
                if let Expr::Name(name_node) = &*node.value {
                    let base_id = name_node.id.as_str();
                    if (base_id == "self" || base_id == "cls") && !self.class_stack.is_empty() {
                        // Resolve self.method or cls.method to Module.Class.method
                        let method_name = &node.attr;
                        let mut parts = Vec::new();
                        if !self.module_name.is_empty() {
                            parts.push(self.module_name.clone());
                        }
                        // Use the current class stack
                        parts.extend(self.class_stack.clone());
                        parts.push(method_name.to_string());
                        let qualified = parts.join(".");
                        self.add_ref(qualified);
                    }
                }
                self.visit_expr(&node.value);
            }
            _ => {}
        }
    }
}
