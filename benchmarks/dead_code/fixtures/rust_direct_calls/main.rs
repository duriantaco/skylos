fn normalize(value: &str) -> usize {
    value.len()
}

fn render(value: &str) -> usize {
    normalize(value)
}

fn summarize(value: &str) -> usize {
    value.len() + 1
}

fn main() {
    println!("{}", render("sample"));
}
