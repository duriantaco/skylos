use std::fs;
use std::path::{Path, PathBuf};

fn state_file() -> PathBuf {
    PathBuf::from("/var/lib/app").join("state.json")
}

fn read_optional(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn main() {
    let _ = read_optional(&state_file());
}
