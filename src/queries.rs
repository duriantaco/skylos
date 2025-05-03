// src/queries.rs
pub const CLASS_QUERY: &str = r#"(class_definition name: (identifier) @class_name) @class"#;
pub const METHOD_QUERY: &str = r#"(function_definition name: (identifier) @method_name) @method"#;
pub const FUNCTION_QUERY: &str = r#"(function_definition name: (identifier) @func_name) @function"#;
pub const IMPORT_QUERY: &str = r#"(import_statement) @import (import_from_statement) @import_from"#;
pub const CALL_QUERY: &str = r#"
(call function: (identifier) @call_func) @call
(call function: (attribute object: (_) @object attribute: (identifier) @method_name)) @call
"#;
pub const DECORATOR_QUERY: &str = r#"
(decorator (identifier) @decorator_name)
(decorator (attribute object: (identifier) @decorator_obj attribute: (identifier) @decorator_attr))
"#;
pub const MAIN_QUERY: &str = r#"(if_statement condition: (_) @cond consequence: (block) @block)"#;
pub const ASSIGN_QUERY: &str = r#"
(assignment left: (identifier) @var right: (call function: (identifier) @cls))
(assignment left: (identifier) @var_method right: (attribute object: (identifier) @obj attribute: (identifier) @method))
"#;