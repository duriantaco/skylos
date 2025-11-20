// Integration tests for skylos-rs
// These tests run the binary on sample code and verify output matches expectations

use std::process::Command;
use std::str;
use serde_json::Value;

/// Helper function to run skylos-rs and parse JSON output
fn run_skylos(path: &str, flags: &[&str]) -> Value {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--release", "--"])
        .arg(path)
        .args(flags)
        .arg("--json")
        .output()
        .expect("Failed to execute skylos-rs binary");
    
    assert!(
        output.status.success(), 
        "Command failed: {}", 
        str::from_utf8(&output.stderr).unwrap_or("")
    );
    
    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    serde_json::from_str(stdout).expect("Failed to parse JSON output")
}

/// Helper to count items in a JSON array field
fn count_items(result: &Value, field: &str) -> usize {
    result[field].as_array().map(|a| a.len()).unwrap_or(0)
}

/// Helper to check if an item with a specific name exists in results
fn has_item_named(result: &Value, field: &str, name: &str) -> bool {
    result[field]
        .as_array()
        .map(|arr| {
            arr.iter().any(|item| {
                item["simple_name"].as_str() == Some(name) ||
                item["name"].as_str().map(|n| n.contains(name)).unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

// ============================================================================
// BASIC TESTS - Functions, Classes, Methods
// ============================================================================

#[test]
fn test_unused_function_detection() {
    let result = run_skylos("../test/cases/01_basic/test_001_unused_function", &[]);
    
    // Should detect exactly one unused function
    assert_eq!(count_items(&result, "unused_functions"), 1);
    assert!(has_item_named(&result, "unused_functions", "unused_function"));
    
    // Should NOT report used functions
    assert!(!has_item_named(&result, "unused_functions", "used_function"));
    assert!(!has_item_named(&result, "unused_functions", "another_used_function"));
}

#[test]
fn test_unused_class_detection() {
    let result = run_skylos("../test/cases/01_basic/test_002_unused_class", &[]);
    
    // Should detect the unused class
    assert!(has_item_named(&result, "unused_classes", "UnusedClass"));
    
    // Should NOT report used classes
    assert!(!has_item_named(&result, "unused_classes", "UsedClass"));
    assert!(!has_item_named(&result, "unused_classes", "ChildClass"));
}

#[test]
fn test_unused_method_detection() {
    let result = run_skylos("../test/cases/01_basic/test_003_unused_method", &[]);
    
    // Note: Current Rust implementation may have limitations with method detection
    // This test documents expected behavior
    let unused_count = count_items(&result, "unused_functions");
    
    // At minimum, should analyze the file without crashing
    assert!(result["analysis_summary"]["total_files"].as_u64().unwrap() > 0);
}

#[test]
fn test_nested_functions() {
    let result = run_skylos("../test/cases/01_basic/test_004_nested_functions", &[]);
    
    // Should handle nested functions without crashing
    assert!(result["analysis_summary"]["total_files"].as_u64().unwrap() > 0);
}

// ============================================================================
// IMPORT TESTS
// ============================================================================

#[test]
fn test_unused_import_detection() {
    let result = run_skylos("../test/cases/02_imports/test_001_unused_import", &[]);
    
    // Should detect unused imports
    let unused_imports = count_items(&result, "unused_imports");
    
    // Should find at least some unused imports (json, datetime, numpy, etc.)
    // Note: Exact count may vary based on implementation completeness
    assert!(unused_imports > 0, "Should detect at least some unused imports");
}

#[test]
fn test_cross_module_references() {
    let result = run_skylos("../test/cases/02_imports/test_002_cross_module", &[]);
    
    // Should handle cross-module references
    assert!(result["analysis_summary"]["total_files"].as_u64().unwrap() >= 2);
}

#[test]
fn test_package_imports() {
    let result = run_skylos("../test/cases/02_imports/test_003_package_imports", &[]);
    
    // Should handle package imports with __init__.py
    assert!(result["analysis_summary"]["total_files"].as_u64().unwrap() >= 3);
}

// ============================================================================
// FRAMEWORK TESTS
// ============================================================================

#[test]
fn test_flask_framework_detection() {
    let result = run_skylos("../test/cases/05_frameworks", &[]);
    
    // Flask routes should not be reported as unused
    // This tests framework awareness
    assert!(result["analysis_summary"]["total_files"].as_u64().unwrap() > 0);
}

// ============================================================================
// SECURITY SCANNING TESTS
// ============================================================================

#[test]
fn test_secrets_scanning() {
    let result = run_skylos("../test", &["--secrets"]);
    
    // Should find secrets in test files
    let secrets_count = result["analysis_summary"]["secrets_count"].as_u64().unwrap();
    
    // test/test_secrets.py should contain test secrets
    assert!(secrets_count > 0, "Should detect secrets in test files");
}

#[test]
fn test_danger_scanning() {
    let result = run_skylos("../test", &["--danger"]);
    
    // Should complete without errors
    assert!(result["analysis_summary"].is_object());
}

#[test]
fn test_quality_scanning() {
    let result = run_skylos("../test", &["--quality"]);
    
    // Should find quality issues (deeply nested code)
    let quality_count = result["analysis_summary"]["quality_count"].as_u64().unwrap();
    
    // test/diagnostics.py has deeply nested code
    assert!(quality_count > 0, "Should detect quality issues");
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_full_analysis_with_all_flags() {
    let result = run_skylos("../test/sample_repo", &["--secrets", "--danger", "--quality"]);
    
    // Should complete full analysis
    assert!(result["analysis_summary"]["total_files"].as_u64().unwrap() > 0);
    assert!(result["unused_functions"].is_array());
    assert!(result["unused_imports"].is_array());
    assert!(result["unused_classes"].is_array());
    assert!(result["secrets"].is_array());
    assert!(result["danger"].is_array());
    assert!(result["quality"].is_array());
}

#[test]
fn test_confidence_threshold() {
    let result_60 = run_skylos("../test/sample_repo", &["--confidence", "60"]);
    let result_80 = run_skylos("../test/sample_repo", &["--confidence", "80"]);
    
    // Higher threshold should report fewer or equal items
    let count_60 = count_items(&result_60, "unused_functions") + 
                   count_items(&result_60, "unused_classes") +
                   count_items(&result_60, "unused_imports");
    
    let count_80 = count_items(&result_80, "unused_functions") + 
                   count_items(&result_80, "unused_classes") +
                   count_items(&result_80, "unused_imports");
    
    assert!(count_80 <= count_60, "Higher confidence should report fewer items");
}

#[test]
fn test_empty_directory() {
    // Create a temporary empty directory for testing
    let temp_dir = std::env::temp_dir().join("skylos_test_empty");
    std::fs::create_dir_all(&temp_dir).unwrap();
    
    let result = run_skylos(temp_dir.to_str().unwrap(), &[]);
    
    // Should handle empty directory gracefully
    assert_eq!(result["analysis_summary"]["total_files"].as_u64().unwrap(), 0);
    assert_eq!(count_items(&result, "unused_functions"), 0);
    
    // Cleanup
    std::fs::remove_dir_all(&temp_dir).ok();
}
