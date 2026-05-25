use std::path::{Path, PathBuf};

fn read_profile(input: String) -> std::io::Result<String> {
    let name = Path::new(&input).file_name().unwrap();
    let mut base = PathBuf::from("/srv/profiles");
    base.push(name);
    std::fs::read_to_string(base)
}
