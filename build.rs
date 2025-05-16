use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=tree-sitter-python");

    let python_exe = env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".to_string());
    println!("cargo:warning=Using Python executable for build.rs checks: {}", python_exe);

    if cfg!(target_os = "macos") {
        let prefix_output = Command::new(&python_exe)
            .arg("-c")
            .arg("import sysconfig; print(sysconfig.get_config_var('prefix'))")
            .output();

        if let Ok(output) = prefix_output {
            if output.status.success() {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!("cargo:warning=Python prefix (for build.rs checks): {}", prefix);

                if prefix.contains("/opt/homebrew") {
                    println!("cargo:warning=Detected Homebrew Python on macOS, applying dynamic_lookup linker args.");
                    println!("cargo:rustc-link-arg=-undefined");
                    println!("cargo:rustc-link-arg=dynamic_lookup");

                    let libdir_output = Command::new(&python_exe)
                        .arg("-c")
                        .arg("import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
                        .output();
                    if let Ok(ld_output) = libdir_output {
                         if ld_output.status.success(){
                            let libdir = String::from_utf8_lossy(&ld_output.stdout).trim().to_string();
                            println!("cargo:warning=Homebrew Python LIBDIR: {}", libdir);
                            println!("cargo:rustc-link-search=native={}", libdir);
                         }
                    }

                } else {
                    println!("cargo:warning=macOS Python detected, but not Homebrew based on prefix. No special linker args applied by build.rs for Python.");
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("cargo:warning=Failed to get Python prefix on macOS: {}", stderr);
            }
        } else {
            println!("cargo:warning=Failed to execute Python to get prefix on macOS.");
        }
    } else {
        println!("cargo:warning=Non-macOS target (e.g., Linux). Relying on PyO3 'extension-module' for Python symbol resolution. No explicit libpython linking in build.rs.");
    }
}
