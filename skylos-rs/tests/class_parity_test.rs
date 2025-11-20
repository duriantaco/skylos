use rustpython_parser::{parse, Mode};
use skylos_rs::utils::LineIndex;
use skylos_rs::visitor::SkylosVisitor;
use std::path::PathBuf;

#[test]
fn test_class_parity_features() {
    let source = r#"
class BaseClass:
    pass

class ChildClass(BaseClass):
    def instance_method(self):
        self.helper()

    def class_method(cls):
        cls.static_helper()
        
    def helper(self):
        pass
        
    def static_helper(cls):
        pass
"#;
    let line_index = LineIndex::new(source);
    let mut visitor = SkylosVisitor::new(
        PathBuf::from("test.py"),
        "test_module".to_string(),
        &line_index,
    );

    let ast = parse(source, Mode::Module, "test.py").unwrap();
    if let rustpython_ast::Mod::Module(module) = ast {
        for stmt in module.body {
            visitor.visit_stmt(&stmt);
        }
    }

    let refs: Vec<String> = visitor.references.iter().map(|r| r.0.clone()).collect();
    println!("References: {:?}", refs);

    // 1. Verify Base Class reference
    assert!(
        refs.contains(&"BaseClass".to_string()),
        "BaseClass should be referenced"
    );

    // 2. Verify self.method() -> ChildClass.helper
    assert!(
        refs.contains(&"test_module.ChildClass.helper".to_string()),
        "self.helper() should resolve to ChildClass.helper"
    );

    // 3. Verify cls.method() -> ChildClass.static_helper
    assert!(
        refs.contains(&"test_module.ChildClass.static_helper".to_string()),
        "cls.static_helper() should resolve to ChildClass.static_helper"
    );
}
