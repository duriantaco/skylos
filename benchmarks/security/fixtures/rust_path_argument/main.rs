fn main() {
    let requested_path = std::env::args().nth(1).unwrap_or_default();
    let _ = std::fs::read_to_string(requested_path);
}
