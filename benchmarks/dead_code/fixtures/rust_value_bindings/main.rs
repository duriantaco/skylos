fn callback() {}
fn render() {}
fn invoke(callback: fn()) { callback(); }

fn main() {
    let callback = render;
    invoke(callback);
}
