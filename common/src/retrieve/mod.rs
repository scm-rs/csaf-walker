//! Retrieving remote content

mod error;
pub use error::*;

use crate::utils::{hex::Hex, url::Urlify};
use digest::{Digest, Output};
use std::{
    fmt::{Debug, Formatter},
    ops::{Deref, DerefMut},
};
use time::OffsetDateTime;

pub trait RetrievedDocument: Urlify + Debug {
    type Discovered: Urlify + Debug;
}

/// The retrieved digest
#[derive(Clone, PartialEq, Eq)]
pub struct RetrievedDigest<D: Digest> {
    /// The expected digest, as read from the remote source
    pub expected: String,
    /// The actual digest, as calculated from reading the content
    pub actual: Output<D>,
}

impl<D: Digest> RetrievedDigest<D> {
    pub fn validate(&self) -> Result<(), (&str, String)> {
        let actual = Hex(&self.actual).to_lower();
        if self.expected.eq_ignore_ascii_case(&actual) {
            Ok(())
        } else {
            Err((&self.expected, actual))
        }
    }
}

impl<D: Digest> Debug for RetrievedDigest<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetrievedDigest")
            .field("expected", &self.expected)
            .field("actual", &Hex(&self.actual))
            .finish()
    }
}

/// Building a digest while retrieving.
#[derive(Clone)]
pub struct RetrievingDigest<D: Digest> {
    pub expected: String,
    pub current: D,
}

impl<D> Deref for RetrievingDigest<D>
where
    D: Digest,
{
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.current
    }
}

impl<D> DerefMut for RetrievingDigest<D>
where
    D: Digest,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.current
    }
}

impl<D> From<RetrievingDigest<D>> for RetrievedDigest<D>
where
    D: Digest,
{
    fn from(value: RetrievingDigest<D>) -> Self {
        Self {
            expected: value.expected,
            actual: value.current.finalize(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sha2::Sha256;

    #[rstest]
    #[case::lowercase("916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9")]
    #[case::uppercase("916F0027A575074CE72A331777C3478D6513F786A591BD892DA1A577BF2335F9")]
    #[case::mixed_case("916F0027a575074ce72A331777C3478d6513F786a591BD892da1A577bf2335F9")]
    fn validate_digest_case_insensitive(#[case] expected: &str) {
        let digest = RetrievedDigest::<Sha256> {
            expected: expected.to_string(),
            actual: Sha256::digest(b"test data"),
        };
        assert!(digest.validate().is_ok());
    }

    #[test]
    fn validate_digest_mismatch() {
        let digest = RetrievedDigest::<Sha256> {
            expected: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            actual: Sha256::digest(b"test data"),
        };
        assert!(digest.validate().is_err());
    }
}

/// Metadata of the retrieval process.
#[derive(Clone, Debug, Default)]
pub struct RetrievalMetadata {
    /// Last known modification time
    pub last_modification: Option<OffsetDateTime>,
    /// ETag
    pub etag: Option<String>,
}
