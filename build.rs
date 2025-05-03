use std::process::Command;
use std::env;
use std::path::Path;
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=tree-sitter-python");

    let python = env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".to_string());
    println!("cargo:warning=Using Python executable: {}", python);

    let prefix_output = Command::new(&python)
        .arg("-c")
        .arg("import sysconfig; print(sysconfig.get_config_var('prefix'))")
        .output()
        .expect("Failed to get Python prefix");
    let prefix = String::from_utf8(prefix_output.stdout)
        .expect("Invalid UTF-8 output from prefix")
        .trim()
        .to_string();
    println!("cargo:warning=Python prefix: {}", prefix);
    
    let libdir_output = Command::new(&python)
        .arg("-c")
        .arg("import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
        .output()
        .expect("Failed to get Python library directory");
    let libdir = String::from_utf8(libdir_output.stdout)
        .expect("Invalid UTF-8 output from LIBDIR")
        .trim()
        .to_string();
    println!("cargo:warning=LIBDIR: {}", libdir);
    
    if prefix.contains("/opt/homebrew") {
        println!("cargo:warning=Detected Homebrew Python, using dynamic lookup linking");
        println!("cargo:rustc-link-search=native={}", libdir);
        
        if cfg!(target_os = "macos") {
            println!("cargo:rustc-link-arg=-undefined");
            println!("cargo:rustc-link-arg=dynamic_lookup");
        }
    } else {
        let version_output = Command::new(&python)
            .arg("-c")
            .arg("import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            .output()
            .expect("Failed to get Python version");
        let version = String::from_utf8(version_output.stdout)
            .expect("Invalid UTF-8 output from version")
            .trim()
            .to_string();
        
        println!("cargo:rustc-link-search=native={}", libdir);
        println!("cargo:rustc-link-lib=python{}", version);
    }
}