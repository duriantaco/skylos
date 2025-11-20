use rustpython_ast::{self as ast, Stmt, ExceptHandler};
use serde::Serialize;
use std::path::PathBuf;
use crate::utils::LineIndex;

#[derive(Debug, Clone, Serialize)]
pub struct QualityFinding {
    pub message: String,
    pub rule_id: String,
    pub file: PathBuf,
    pub line: usize,
    pub severity: String,
}

pub struct QualityVisitor<'a> {
    pub findings: Vec<QualityFinding>,
    pub file_path: PathBuf,
    pub line_index: &'a LineIndex,
    pub current_depth: usize,
    pub max_depth: usize,
}

impl<'a> QualityVisitor<'a> {
    pub fn new(file_path: PathBuf, line_index: &'a LineIndex) -> Self {
        Self {
            findings: Vec::new(),
            file_path,
            line_index,
            current_depth: 0,
            max_depth: 5,
        }
    }

    fn check_depth(&mut self, range_start: rustpython_ast::TextSize) {
        if self.current_depth > self.max_depth {
            let line = self.line_index.line_index(range_start);
            self.add_finding(
                &format!("Deeply nested code (depth {})", self.current_depth),
                "SKY-Q001",
                line,
            );
        }
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::FunctionDef(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::AsyncFunctionDef(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::ClassDef(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::If(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                for stmt in &node.orelse {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::For(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                for stmt in &node.orelse {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::AsyncFor(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                for stmt in &node.orelse {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::While(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                for stmt in &node.orelse {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::Try(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                for handler in &node.handlers {
                    match handler {
                        ExceptHandler::ExceptHandler(h) => {
                            for stmt in &h.body {
                                self.visit_stmt(stmt);
                            }
                        }
                    }
                }
                for stmt in &node.orelse {
                    self.visit_stmt(stmt);
                }
                for stmt in &node.finalbody {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::With(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            Stmt::AsyncWith(node) => {
                self.current_depth += 1;
                self.check_depth(node.range.start());
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
                self.current_depth -= 1;
            }
            _ => {}
        }
    }

    fn add_finding(&mut self, msg: &str, rule_id: &str, line: usize) {
        if let Some(last) = self.findings.last() {
            if last.line == line && last.rule_id == rule_id {
                return;
            }
        }
        
        self.findings.push(QualityFinding {
            message: msg.to_string(),
            rule_id: rule_id.to_string(),
            file: self.file_path.clone(),
            line,
            severity: "LOW".to_string(),
        });
    }
}
