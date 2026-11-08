pub struct Card {}
pub trait Stamp { fn stamp(&self) -> u8; }
impl Stamp for Card { fn stamp(&self) -> u8 { 1 } }
pub trait Retired { fn retired(&self) -> u8; }
impl Retired for Card { fn retired(&self) -> u8 { 2 } }
