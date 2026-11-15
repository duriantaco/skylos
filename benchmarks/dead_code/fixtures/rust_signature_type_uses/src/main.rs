use std::collections::BTreeSet;
use std::fmt::Debug;
use std::ops::{Add, Sub};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

// Rc was replaced by plain ownership.
const NOTE: &str = "Rc is no longer needed";

trait Numeric: Add<Output = Self> + Copy {}

impl<T: Sub<Output = T> + Add<Output = T> + Copy> Numeric for T {}

struct Wrapper<T: Debug> {
    value: T,
}

impl<T> Wrapper<T>
where
    T: Into<Duration> + Debug,
{
    fn seconds(self) -> u64 {
        self.value.into().as_secs()
    }
}

fn target() -> PathBuf {
    "out".into()
}

fn double<T: Numeric>(value: T) -> T {
    value + value
}

fn main() {
    let wrapped = Wrapper { value: Duration::from_secs(2) };
    println!("{} {:?} {} {}", wrapped.seconds(), target(), double(2), NOTE);
}
