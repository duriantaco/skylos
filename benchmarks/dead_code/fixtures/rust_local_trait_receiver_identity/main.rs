
struct Card {}
struct Badge {}
mod traits {
    pub trait Stamp { fn stamp(&self) -> u8; }
    pub trait Other { fn stamp(&self) -> u8; }
    pub trait Retired { fn retired(&self) -> u8; }
    impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }
    impl Other for super::Badge { fn stamp(&self) -> u8 { 2 } }
    impl Retired for super::Card { fn retired(&self) -> u8 { 3 } }
}
use crate::traits::Stamp as Active;
use crate::traits::Retired as Inactive;
fn main() { let value = Card {}; let _ = value.stamp(); }

fn orphan() -> u8 { 0 }
