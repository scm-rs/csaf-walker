//! Common helpers for implementing sources

use crate::retrieve::RetrievedDocument;
use std::fmt::{Debug, Display};

pub mod file;

pub trait Source: Send + Sync {
    type Error: Display + Debug + Send;
    type Retrieved: RetrievedDocument;
}
