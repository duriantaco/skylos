use std::fs;
use std::path::Path;

pub fn walk(dir: &Path) -> Vec<u8> {
    fs::read(dir.join("ids.json")).unwrap()
}
