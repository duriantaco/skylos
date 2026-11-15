use std::fs;
use std::path::Path;

mod remote;

fn read_optional(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

pub fn load_state() -> Vec<u8> {
    read_optional(Path::new("/var/lib/app/state.json"))
}
