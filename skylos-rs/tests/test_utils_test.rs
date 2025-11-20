// Unit tests for test awareness
// Tests detection of test files and test functions

use skylos_rs::test_utils::TestAwareVisitor;
use skylos_rs::utils::LineIndex;
use rustpython_parser::{parse, Mode};
use std::path::PathBuf;

#[test]
fn test_pytest_function_detection() {
    let source = r#"
def test_something():
    assert True

def test_another_thing():
    assert 1 + 1 == 2

def regular_function():
    return 42
"#;
    
    let tree = parse(source, Mode::Module, "test_file.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = TestAwareVisitor::new(PathBuf::from("test_file.py"), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    // Should detect test functions
    assert!(visitor.test_decorated_lines.len() >= 2, "Should detect test functions");
}

#[test]
fn test_file_name_detection() {
    let test_files = vec![
        "test_module.py",
        "module_test.py",
        "conftest.py",
        "tests.py",
    ];
    
    for filename in test_files {
        let source = "def foo(): pass";
        let _tree = parse(source, Mode::Module, filename).expect("Failed to parse");
        let line_index = LineIndex::new(source);
        let visitor = TestAwareVisitor::new(PathBuf::from(filename), &line_index);
        
        assert!(visitor.is_test_file, "Should detect {} as test file", filename);
    }
}

#[test]
fn test_non_test_file_detection() {
    let source = "def foo(): pass";
    let _tree = parse(source, Mode::Module, "regular_module.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let visitor = TestAwareVisitor::new(PathBuf::from("regular_module.py"), &line_index);
    
    assert!(!visitor.is_test_file, "Should not detect regular file as test file");
}
