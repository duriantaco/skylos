fn consume(value: u8) { let _ = value; }
pub fn run(flag: bool) {
    if flag {
        let value = 1;
        consume(value);
    } else {
        let value = 2;
        consume(value);
    }
}
