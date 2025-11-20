// Unit tests for security rules
// Tests secrets and dangerous code detection

use skylos_rs::rules::secrets::scan_secrets;
use skylos_rs::rules::danger::DangerVisitor;
use skylos_rs::utils::LineIndex;
use rustpython_parser::{parse, Mode};
use std::path::PathBuf;

#[test]
fn test_aws_key_detection() {
    let source = r#"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"#;
    
    let findings = scan_secrets(source, &PathBuf::from("test.py"));
    
    assert!(findings.len() >= 1, "Should detect AWS keys");
}

#[test]
fn test_no_secrets_in_clean_code() {
    let source = r#"
def calculate(x, y):
    return x + y

API_URL = "https://api.example.com"
"#;
    
    let findings = scan_secrets(source, &PathBuf::from("test.py"));
    
    // Should not detect false positives
    assert_eq!(findings.len(), 0, "Should not detect secrets in clean code");
}

#[test]
fn test_eval_detection() {
    let source = r#"
user_input = input("Enter code: ")
result = eval(user_input)
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = DangerVisitor::new(PathBuf::from("test.py"), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    assert!(visitor.findings.len() > 0, "Should detect eval usage");
    assert!(visitor.findings.iter().any(|f| f.message.contains("eval")));
}

#[test]
fn test_exec_detection() {
    let source = r#"
code = "print('hello')"
exec(code)
"#;
    
    let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
    let line_index = LineIndex::new(source);
    let mut visitor = DangerVisitor::new(PathBuf::from("test.py"), &line_index);
    
    for stmt in &tree.body {
        visitor.visit_stmt(stmt);
    }
    
    assert!(visitor.findings.len() > 0, "Should detect exec usage");
}
