use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let chosen = PathBuf::from(env::var("GENERATED_TARGET").unwrap());
    fs::write(chosen, "pub const SIZE: usize = 4;").unwrap();
}
