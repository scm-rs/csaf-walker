//! Command line helpers
pub mod client;
pub mod parser;
pub mod runner;

#[cfg(feature = "openpgp")]
pub mod validation;

#[cfg(feature = "env_logger")]
pub mod log;

pub trait CommandDefaults {
    fn progress(&self) -> bool {
        true
    }
}
