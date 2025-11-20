use rustpython_parser::{parse, Mode};
use skylos_rs::utils::LineIndex;
use skylos_rs::visitor::SkylosVisitor;
use std::path::PathBuf;

fn main() {
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
        PathBuf::from("test_parity.py"),
        "test_parity".to_string(),
        &line_index,
    );

    let ast = parse(source, Mode::Module, "test_parity.py").unwrap();
    if let rustpython_ast::Mod::Module(module) = ast {
        for stmt in module.body {
            visitor.visit_stmt(&stmt);
        }
    }

    println!("=== DEFINITIONS ===");
    for def in &visitor.definitions {
        println!("{}: {} (line {})", def.name, def.def_type, def.line);
    }

    println!("\n=== REFERENCES ===");
    for (ref_name, _) in &visitor.references {
        println!("{}", ref_name);
    }
}
