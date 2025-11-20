use rustpython_ast::{self as ast, Stmt, Expr};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use crate::utils::LineIndex;

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
}

pub struct SkylosVisitor<'a> {
    pub definitions: Vec<Definition>,
    pub references: Vec<(String, PathBuf)>,
    pub file_path: PathBuf,
    pub module_name: String,
    pub current_scope: Vec<String>,
    pub line_index: &'a LineIndex,
}

impl<'a> SkylosVisitor<'a> {
    pub fn new(file_path: PathBuf, module_name: String, line_index: &'a LineIndex) -> Self {
        Self {
            definitions: Vec::new(),
            references: Vec::new(),
            file_path,
            module_name,
            current_scope: Vec::new(),
            line_index,
        }
    }

    fn add_def(&mut self, name: String, def_type: &str, line: usize) {
        let simple_name = name.split('.').last().unwrap_or(&name).to_string();
        let in_init = self.file_path.ends_with("__init__.py");
        
        self.definitions.push(Definition {
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
        });
    }

    fn add_ref(&mut self, name: String) {
        self.references.push((name, self.file_path.clone()));
    }
    
    fn get_qualified_name(&self, name: &str) -> String {
        if self.module_name.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.module_name, name)
        }
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::FunctionDef(node) => {
                let name = &node.name;
                let qualified_name = self.get_qualified_name(name.as_str());
                let line = self.line_index.line_index(node.range.start());
                self.add_def(qualified_name, "function", line);
                
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            Stmt::ClassDef(node) => {
                let name = &node.name;
                let qualified_name = self.get_qualified_name(name.as_str());
                let line = self.line_index.line_index(node.range.start());
                self.add_def(qualified_name, "class", line);
                
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            Stmt::Import(node) => {
                 for alias in &node.names {
                    let asname = alias.asname.as_ref().unwrap_or(&alias.name);
                    let line = self.line_index.line_index(node.range.start());
                    self.add_def(asname.to_string(), "import", line);
                 }
            }
            Stmt::ImportFrom(node) => {
                 // TODO: Handle import from
            }
            Stmt::Expr(node) => {
                self.visit_expr(&node.value);
            }
            _ => {} // TODO: Visit other statements
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
                self.visit_expr(&node.value);
            }
            _ => {} 
        }
    }
}
