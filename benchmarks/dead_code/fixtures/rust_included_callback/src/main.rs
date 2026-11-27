include!("routes.inc");

fn on_event() -> usize {
    7
}

fn old_handler() -> usize {
    2
}

fn main() {
    std::hint::black_box(route());
}
