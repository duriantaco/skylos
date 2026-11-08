use std::io::Write as Output;
use std::io::Read as SpareRead;
#[cfg(feature = "checked")]
use no_panic::no_panic as Applied;
#[cfg(feature = "checked")]
use no_panic::no_panic as SpareAttribute;

#[cfg_attr(feature = "checked", Applied)]
fn value() -> u8 { 7 }

fn main() {
    let mut buffer = Vec::with_capacity(20);
    writeln!(&mut buffer, "{}", value()).unwrap();
}
