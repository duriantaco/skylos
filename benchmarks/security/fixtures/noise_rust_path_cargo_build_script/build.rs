use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("table.rs");
    fs::write(out, "pub const SIZE: usize = 4;").unwrap();
}
