fn callback() {}
fn chosen() {}
fn target() {}
fn fallback() {}
fn choice() -> Option<fn()> { Some(chosen) }

fn abandoned() {
    let selected = callback;
    selected();
}

fn main() {
    { let target: fn() = chosen; target(); }
    target();
    match choice() {
        Some(callback) => callback(),
        None => fallback(),
    }
}
