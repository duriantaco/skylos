use rustpython_ast::{self as ast, Stmt, Expr};
use std::collections::HashSet;
use crate::utils::LineIndex;

lazy_static::lazy_static! {
    static ref FRAMEWORK_IMPORTS: HashSet<&'static str> = {
        let mut s = HashSet::new();
        s.insert("flask");
        s.insert("fastapi");
        s.insert("django");
        s.insert("rest_framework");
        s.insert("pydantic");
        s.insert("celery");
        s.insert("starlette");
        s.insert("uvicorn");
        s
    };
}

pub struct FrameworkAwareVisitor<'a> {
    pub is_framework_file: bool,
    pub detected_frameworks: HashSet<String>,
    pub framework_decorated_lines: HashSet<usize>,
    pub line_index: &'a LineIndex,
}

impl<'a> FrameworkAwareVisitor<'a> {
    pub fn new(line_index: &'a LineIndex) -> Self {
        Self {
            is_framework_file: false,
            detected_frameworks: HashSet::new(),
            framework_decorated_lines: HashSet::new(),
            line_index,
        }
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(node) => {
                for alias in &node.names {
                    let name = alias.name.as_str();
                    for fw in FRAMEWORK_IMPORTS.iter() {
                        if name.contains(fw) {
                            self.is_framework_file = true;
                            self.detected_frameworks.insert(fw.to_string());
                        }
                    }
                }
            }
            Stmt::ImportFrom(node) => {
                if let Some(module) = &node.module {
                    let module_name = module.split('.').next().unwrap_or("");
                    if FRAMEWORK_IMPORTS.contains(module_name) {
                        self.is_framework_file = true;
                        self.detected_frameworks.insert(module_name.to_string());
                    }
                }
            }
            Stmt::FunctionDef(node) => {
                let line = self.line_index.line_index(node.range.start());
                self.check_decorators(&node.decorator_list, line);
                // Recurse
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            Stmt::ClassDef(node) => {
                // Check base classes
                for base in &node.bases {
                    if let Expr::Name(name_node) = base {
                        let id = name_node.id.to_lowercase();
                        if id.contains("view") || id.contains("model") || id.contains("schema") {
                             self.is_framework_file = true;
                             let line = self.line_index.line_index(node.range.start());
                             self.framework_decorated_lines.insert(line);
                        }
                    }
                }
                
                // Recurse
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            _ => {}
        }
    }

    fn check_decorators(&mut self, decorators: &[Expr], line: usize) {
        for decorator in decorators {
            let name = self.get_decorator_name(decorator);
            if self.is_framework_decorator(&name) {
                self.framework_decorated_lines.insert(line);
                self.is_framework_file = true;
            }
        }
    }

    fn get_decorator_name(&self, decorator: &Expr) -> String {
        match decorator {
            Expr::Name(node) => node.id.to_string(),
            Expr::Attribute(node) => {
                node.attr.to_string()
            }
            Expr::Call(node) => self.get_decorator_name(&node.func),
            _ => String::new(),
        }
    }

    fn is_framework_decorator(&self, name: &str) -> bool {
        let name = name.to_lowercase();
        name.contains("route") || 
        name.contains("get") || 
        name.contains("post") || 
        name.contains("put") || 
        name.contains("delete") ||
        name.contains("validator") ||
        name.contains("task") // celery
    }
}
