use skylos_rs::visitor::SkylosVisitor;
use skylos_rs::utils::LineIndex;
use rustpython_parser::{parse, Mode};
use std::path::PathBuf;

#[test]
fn test_class_method_context() {
    let source = r#"
class MyClass:
    def my_method(self):
        pass

    def another_method(self):
        self.my_method()
"#;
    let line_index = LineIndex::new(source);
    let mut visitor = SkylosVisitor::new(PathBuf::from("test.py"), "test_module".to_string(), &line_index);
    
    let ast = parse(source, Mode::Module, "test.py").unwrap();
    if let rustpython_ast::Mod::Module(module) = ast {
        for stmt in module.body {
            visitor.visit_stmt(&stmt);
        }
    }

    // Check definitions
    let defs: Vec<String> = visitor.definitions.iter().map(|d| d.full_name.clone()).collect();
    println!("Definitions: {:?}", defs);
    assert!(defs.contains(&"test_module.MyClass".to_string()));
    assert!(defs.contains(&"test_module.MyClass.my_method".to_string()));
    assert!(defs.contains(&"test_module.MyClass.another_method".to_string()));

    // Check references
    let refs: Vec<String> = visitor.references.iter().map(|r| r.0.clone()).collect();
    println!("References: {:?}", refs);
    assert!(refs.contains(&"test_module.MyClass.my_method".to_string()));
}
