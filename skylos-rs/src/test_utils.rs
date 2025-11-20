use rustpython_ast::{self as ast, Stmt, Expr};
use regex::Regex;
use std::path::Path;
use crate::utils::LineIndex;

lazy_static::lazy_static! {
    static ref TEST_FILE_RE: Regex = Regex::new(r"(^|/|\\)(test_|tests|conftest)").unwrap();
}

pub struct TestAwareVisitor<'a> {
    pub is_test_file: bool,
    pub test_decorated_lines: Vec<usize>,
    pub line_index: &'a LineIndex,
}

impl<'a> TestAwareVisitor<'a> {
    pub fn new(path: &Path, line_index: &'a LineIndex) -> Self {
        let path_str = path.to_string_lossy();
        let is_test_file = TEST_FILE_RE.is_match(&path_str) || path_str.ends_with("_test.py");
        
        Self {
            is_test_file,
            test_decorated_lines: Vec::new(),
            line_index,
        }
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::FunctionDef(node) => {
                let name = &node.name;
                let line = self.line_index.line_index(node.range.start());
                
                if name.starts_with("test_") || name.ends_with("_test") {
                    self.test_decorated_lines.push(line);
                }
                
                // Check decorators
                for decorator in &node.decorator_list {
                    if let Expr::Name(name_node) = decorator {
                        if name_node.id.contains("pytest") || name_node.id.contains("fixture") {
                            self.test_decorated_lines.push(line);
                        }
                    } else if let Expr::Attribute(attr_node) = decorator {
                        if attr_node.attr.contains("pytest") || attr_node.attr.contains("fixture") {
                            self.test_decorated_lines.push(line);
                        }
                    }
                }
                
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            Stmt::ClassDef(node) => {
                let name = &node.name;
                if name.starts_with("Test") || name.ends_with("Test") {
                    let line = self.line_index.line_index(node.range.start());
                    self.test_decorated_lines.push(line);
                }
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            _ => {}
        }
    }
}
