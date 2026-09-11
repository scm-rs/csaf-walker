//! Helpers for working with "OpenPGP".
use bytes::Bytes;
use sequoia_openpgp::{Cert, cert::CertParser, parse::Parse};
use std::fmt::Debug;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OpenPGP key error: {0}")]
    OpenPgp(#[from] anyhow::Error),
    #[error("Expected public key, found: {0}")]
    WrongKeyType(String),
    #[error("Fingerprint mismatch - expected: {expected}, actual: {actual}")]
    FingerprintMismatch { actual: String, expected: String },
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub certs: Vec<Cert>,
    pub raw: Bytes,
}

pub fn validate_keys(bytes: Bytes, fingerprint: Option<&str>) -> Result<PublicKey, Error> {
    let certs = CertParser::from_bytes(&bytes)?.collect::<Result<Vec<_>, _>>()?;

    for cert in &certs {
        if let Some(expected) = &fingerprint {
            let actual = cert.fingerprint().to_hex();
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(Error::FingerprintMismatch {
                    actual,
                    expected: expected.to_string(),
                });
            }
        }
    }

    Ok(PublicKey { certs, raw: bytes })
}
