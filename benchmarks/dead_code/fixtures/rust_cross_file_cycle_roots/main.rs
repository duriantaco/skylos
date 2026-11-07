mod child;

fn alpha(depth: u8) {
    if depth > 0 { beta(depth - 1); }
}
fn beta(depth: u8) { alpha(depth); }
fn unused_leaf() {}

fn main() { child::start(); }
