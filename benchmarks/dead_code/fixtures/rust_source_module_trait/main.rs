mod model;
use model::Stamp as Active;
use model::Retired as Inactive;
fn main() { let value = model::Card {}; let _ = value.stamp(); }
fn orphan() {}
