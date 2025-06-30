//! Handle "hex" encoding

use std::fmt::{Debug, Formatter, LowerHex};

pub struct Hex<'a>(pub &'a [u8]);

impl Hex<'_> {
    pub fn to_lower(&self) -> String {
        format!("{self:x}")
    }
}

impl Debug for Hex<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:x}")
    }
}

impl LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
