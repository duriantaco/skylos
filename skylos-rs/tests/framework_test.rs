// Unit tests for framework awareness
// Tests detection of Flask, Django, FastAPI patterns

use skylos_rs::framework::FrameworkAwareVisitor;
use skylos_rs::utils::LineIndex;
use rustpython_parser::{parse, Mode};
use std::path::PathBuf;

#[test]
fn test_flask_route_detection() {
    let source = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/home')
def home():
    return "Hello"
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = FrameworkAwareVisitor::new(PathBuf::from("test.py"), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should detect Flask framework
    assert!(visitor.framework_lines.len() > 0 || visitor.framework_imports.len() > 0, 
            "Should detect Flask route or import");
}

#[test]
fn test_no_framework_detection() {
    let source = r#"
def regular_function():
    return 42
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = FrameworkAwareVisitor::new(PathBuf::from("test.py"), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should not detect any framework
    assert_eq!(visitor.framework_lines.len(), 0);
}
