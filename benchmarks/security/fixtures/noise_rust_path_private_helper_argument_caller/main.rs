use std::fs;
use std::path::Path;

fn read_optional(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn main() {
    let _ = read_optional(Path::new("/var/lib/app/state.json"));
    let first = std::env::args().nth(1).unwrap_or_default();
    let _ = read_optional(Path::new(&first));
}
