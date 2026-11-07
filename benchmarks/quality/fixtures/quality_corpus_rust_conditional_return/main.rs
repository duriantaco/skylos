fn consume(value: u8) { let _ = value; }
pub fn run(flag: bool) {
    if flag { return; }
    consume(1);
}
