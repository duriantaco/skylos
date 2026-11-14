use std::path::Path;

pub fn load_named(file_name: &str) -> Vec<u8> {
    super::read_optional(Path::new(file_name))
}
