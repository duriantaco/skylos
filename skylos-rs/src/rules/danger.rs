use rustpython_ast::{self as ast, Expr, Stmt};
use serde::Serialize;
use std::path::PathBuf;
use crate::utils::LineIndex;

#[derive(Debug, Clone, Serialize)]
pub struct DangerFinding {
    pub message: String,
    pub rule_id: String,
    pub file: PathBuf,
    pub line: usize,
    pub severity: String,
}

pub struct DangerVisitor<'a> {
    pub findings: Vec<DangerFinding>,
    pub file_path: PathBuf,
    pub line_index: &'a LineIndex,
}

impl<'a> DangerVisitor<'a> {
    pub fn new(file_path: PathBuf, line_index: &'a LineIndex) -> Self {
        Self {
            findings: Vec::new(),
            file_path,
            line_index,
        }
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Expr(node) => self.visit_expr(&node.value),
            Stmt::FunctionDef(node) => {
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            Stmt::ClassDef(node) => {
                for stmt in &node.body {
                    self.visit_stmt(stmt);
                }
            }
            // Recurse for other statements
            _ => {} 
        }
    }

    pub fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(node) => {
                self.check_call(node);
                self.visit_expr(&node.func);
                for arg in &node.args {
                    self.visit_expr(arg);
                }
            }
            _ => {}
        }
    }

    fn check_call(&mut self, call: &ast::ExprCall) {
        if let Some(name) = self.get_call_name(&call.func) {
            let line = self.line_index.line_index(call.range.start());
            
            if name == "eval" || name == "exec" {
                self.add_finding("Avoid using eval/exec", "SKY-D001", line);
            }
            
            if name == "subprocess.call" || name == "subprocess.Popen" || name == "subprocess.run" {
                // Check for shell=True
                for keyword in &call.keywords {
                    if let Some(arg) = &keyword.arg {
                        if arg == "shell" {
                             if let Expr::Constant(c) = &keyword.value {
                                 if let ast::Constant::Bool(true) = c.value {
                                     self.add_finding("subprocess with shell=True", "SKY-D002", line);
                                 }
                             }
                        }
                    }
                }
            }
        }
    }

    fn get_call_name(&self, func: &Expr) -> Option<String> {
        match func {
            Expr::Name(node) => Some(node.id.to_string()),
            Expr::Attribute(node) => {
                if let Expr::Name(value) = &*node.value {
                    Some(format!("{}.{}", value.id, node.attr))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn add_finding(&mut self, msg: &str, rule_id: &str, line: usize) {
        self.findings.push(DangerFinding {
            message: msg.to_string(),
            rule_id: rule_id.to_string(),
            file: self.file_path.clone(),
            line,
            severity: "CRITICAL".to_string(),
        });
    }
}
