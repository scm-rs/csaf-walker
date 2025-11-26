#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

pub mod changes;
pub mod compression;
pub mod fetcher;
pub mod http;
pub mod locale;
pub mod progress;
pub mod report;
pub mod retrieve;
pub mod scoop;
pub mod sender;
pub mod since;
pub mod source;
pub mod store;
pub mod utils;

#[cfg(feature = "openpgp")]
pub mod validate;

#[cfg(feature = "clap")]
pub mod cli;

/// The user agent used when making HTTP requests
pub const USER_AGENT: &str = concat!("CSAF-Walker/", env!("CARGO_PKG_VERSION"));
