fn alpha() { beta(); }
fn beta() { alpha(); }
fn unused_leaf() {}

fn run_first(depth: u8) {
    if depth > 0 { run_second(depth - 1); }
}
fn run_second(depth: u8) { run_first(depth); }
fn callback() {}
pub fn factory() -> fn() { callback }

fn main() {
    run_first(2);
    let run = factory();
    run();
}
