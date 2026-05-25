use std::process::Command;

fn main() {
    let branch = std::env::args().nth(1).unwrap_or_default();
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("git checkout {}", branch))
        .status();
}
