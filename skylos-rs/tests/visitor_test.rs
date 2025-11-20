// Unit tests for the visitor module
// Tests AST traversal and definition/reference collection

use skylos_rs::visitor::SkylosVisitor;
use skylos_rs::utils::LineIndex;
use rustpython_parser::{parse, Mode};
use std::path::PathBuf;

#[test]
fn test_visitor_detects_function_definition() {
    let source = r#"
def my_function():
    pass
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = SkylosVisitor::new(PathBuf::from("test.py"), "test".to_string(), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should detect one function definition
    assert_eq!(visitor.definitions.len(), 1);
    assert_eq!(visitor.definitions[0].simple_name, "my_function");
    assert_eq!(visitor.definitions[0].def_type, "function");
}

#[test]
fn test_visitor_detects_class_definition() {
    let source = r#"
class MyClass:
    def __init__(self):
        pass
    
    def method(self):
        pass
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = SkylosVisitor::new(PathBuf::from("test.py"), "test".to_string(), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should detect class and its methods
    let class_defs: Vec<_> = visitor.definitions.iter()
        .filter(|d| d.def_type == "class")
        .collect();
    
    assert_eq!(class_defs.len(), 1);
    assert_eq!(class_defs[0].simple_name, "MyClass");
}

#[test]
fn test_visitor_detects_imports() {
    let source = r#"
import os
import sys
from pathlib import Path
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = SkylosVisitor::new(PathBuf::from("test.py"), "test".to_string(), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should detect imports
    let imports: Vec<_> = visitor.definitions.iter()
        .filter(|d| d.def_type == "import")
        .collect();
    
    assert!(imports.len() >= 2, "Should detect at least os and sys imports");
}

#[test]
fn test_visitor_detects_references() {
    let source = r#"
def helper():
    return 42

def main():
    result = helper()
    return result
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = SkylosVisitor::new(PathBuf::from("test.py"), "test".to_string(), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should detect reference to 'helper'
    assert!(visitor.references.iter().any(|(r, _)| r.contains("helper")));
}

#[test]
fn test_line_index_accuracy() {
    let source = "line1\nline2\nline3\n";
    let line_index = LineIndex::new(source);
    
    // Test line number calculation
    assert_eq!(line_index.line_index(0.into()), 1);
    assert_eq!(line_index.line_index(6.into()), 2);
    assert_eq!(line_index.line_index(12.into()), 3);
}
