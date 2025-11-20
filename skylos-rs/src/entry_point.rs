use rustpython_ast::{Stmt, Expr, ExprContext, Constant};
use std::collections::HashSet;

/// Detects if __name__ == "__main__" blocks and extracts function calls
pub fn detect_entry_point_calls(stmts: &[Stmt]) -> HashSet<String> {
    let mut entry_point_calls = HashSet::new();
    
    for stmt in stmts {
        if is_main_guard(stmt) {
            // Extract all function calls from the if block
            if let Stmt::If(if_stmt) = stmt {
                for body_stmt in &if_stmt.body {
                    collect_function_calls(body_stmt, &mut entry_point_calls);
                }
            }
        }
    }
    
    entry_point_calls
}

/// Check if this is an `if __name__ == "__main__"` statement
fn is_main_guard(stmt: &Stmt) -> bool {
    if let Stmt::If(if_stmt) = stmt {
        if let Expr::Compare(compare) = &*if_stmt.test {
            // Check for: __name__ == "__main__" or "__main__" == __name__
            if compare.ops.len() == 1 && compare.comparators.len() == 1 {
                let left = &*compare.left;
                let right = &compare.comparators[0];
                
                return is_name_dunder(left) && is_main_string(right) ||
                       is_name_dunder(right) && is_main_string(left);
            }
        }
    }
    false
}

/// Check if expression is __name__
fn is_name_dunder(expr: &Expr) -> bool {
    if let Expr::Name(name_expr) = expr {
        return name_expr.id.as_str() == "__name__";
    }
    false
}

/// Check if expression is the string "__main__"
fn is_main_string(expr: &Expr) -> bool {
    if let Expr::Constant(const_expr) = expr {
        if let Constant::Str(s) = &const_expr.value {
            return s.as_str() == "__main__";
        }
    }
    false
}

/// Recursively collect all function calls from a statement
fn collect_function_calls(stmt: &Stmt, calls: &mut HashSet<String>) {
    match stmt {
        Stmt::Expr(expr_stmt) => {
            collect_calls_from_expr(&expr_stmt.value, calls);
        }
        Stmt::Assign(assign) => {
            collect_calls_from_expr(&assign.value, calls);
        }
        Stmt::If(if_stmt) => {
            for body_stmt in &if_stmt.body {
                collect_function_calls(body_stmt, calls);
            }
            for else_stmt in &if_stmt.orelse {
                collect_function_calls(else_stmt, calls);
            }
        }
        Stmt::For(for_stmt) => {
            collect_calls_from_expr(&for_stmt.iter, calls);
            for body_stmt in &for_stmt.body {
                collect_function_calls(body_stmt, calls);
            }
        }
        Stmt::While(while_stmt) => {
            for body_stmt in &while_stmt.body {
                collect_function_calls(body_stmt, calls);
            }
        }
        _ => {}
    }
}

/// Extract function names from call expressions
fn collect_calls_from_expr(expr: &Expr, calls: &mut HashSet<String>) {
    match expr {
        Expr::Call(call) => {
            // Get the function name
            if let Some(name) = get_call_name(&call.func) {
                calls.insert(name);
            }
            // Check arguments for nested calls
            for arg in &call.args {
                collect_calls_from_expr(arg, calls);
            }
        }
        Expr::Attribute(attr) => {
            // Handle method calls like obj.method()
            collect_calls_from_expr(&attr.value, calls);
        }
        Expr::BinOp(binop) => {
            collect_calls_from_expr(&binop.left, calls);
            collect_calls_from_expr(&binop.right, calls);
        }
        _ => {}
    }
}

/// Extract function name from call expression
fn get_call_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.to_string()),
        Expr::Attribute(attr) => {
            // For method calls, get the method name
            Some(attr.attr.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustpython_parser::{parse, Mode};

    #[test]
    fn test_entry_point_detection() {
        let source = r#"
def my_function():
    pass

if __name__ == "__main__":
    my_function()
    another_call()
"#;
        
        let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
        if let rustpython_ast::Mod::Module(module) = tree {
            let calls = detect_entry_point_calls(&module.body);
            
            assert!(calls.contains("my_function"), "Should detect my_function call");
            assert!(calls.contains("another_call"), "Should detect another_call");
        }
    }

    #[test]
    fn test_no_entry_point() {
        let source = r#"
def my_function():
    pass
"#;
        
        let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
        if let rustpython_ast::Mod::Module(module) = tree {
            let calls = detect_entry_point_calls(&module.body);
            assert_eq!(calls.len(), 0, "Should detect no entry point calls");
        }
    }

    #[test]
    fn test_reversed_main_guard() {
        let source = r#"
def func():
    pass

if "__main__" == __name__:
    func()
"#;
        
        let tree = parse(source, Mode::Module, "test.py").expect("Failed to parse");
        if let rustpython_ast::Mod::Module(module) = tree {
            let calls = detect_entry_point_calls(&module.body);
            assert!(calls.contains("func"), "Should handle reversed comparison");
        }
    }
}
