use std::fs;

#[cfg(not(test))]
pub fn export(path: &str, data: &[u8]) {
    fs::write(path, data).unwrap();
}
