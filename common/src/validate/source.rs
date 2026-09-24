//! Working with the source in the context of validation.
use crate::{fetcher, fetcher::Fetcher, utils, utils::openpgp::PublicKey};
use bytes::Bytes;
use std::fmt::{Debug, Display};
use std::future::Future;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key<'a> {
    pub fingerprint: Option<&'a str>,
    pub url: &'a Url,
}

#[derive(Debug, thiserror::Error)]
pub enum KeySourceError<SE: Display + Debug> {
    #[error("Key source error: {0}")]
    Source(SE),
    #[error("Key error: {0}")]
    OpenPgp(utils::openpgp::Error),
}

pub trait MapSourceError<T, SE> {
    fn map_source<F, TE>(self, f: F) -> Result<T, KeySourceError<TE>>
    where
        F: FnOnce(SE) -> TE,
        TE: Display + Debug;
}

impl<T, SE: Display + Debug> MapSourceError<T, SE> for Result<T, KeySourceError<SE>> {
    fn map_source<F, TE>(self, f: F) -> Result<T, KeySourceError<TE>>
    where
        F: FnOnce(SE) -> TE,
        TE: Display + Debug,
    {
        self.map_err(|err| err.map_source(f))
    }
}

impl<SE: Display + Debug> KeySourceError<SE> {
    pub fn map_source<F, E>(self, f: F) -> KeySourceError<E>
    where
        F: FnOnce(SE) -> E,
        E: Display + Debug,
    {
        match self {
            Self::Source(err) => KeySourceError::Source(f(err)),
            Self::OpenPgp(err) => KeySourceError::OpenPgp(err),
        }
    }
}

/// A source of CSAF public keys
pub trait KeySource: Clone + Send + Sync {
    type Error: Display + Debug + Send;

    fn load_public_key(
        &self,
        key: Key<'_>,
    ) -> impl Future<Output = Result<PublicKey, KeySourceError<Self::Error>>> + Send;
}

impl KeySource for Fetcher {
    type Error = fetcher::Error;

    async fn load_public_key(
        &self,
        key_source: Key<'_>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        let bytes = self
            .fetch::<Bytes>(key_source.url.clone())
            .await
            .map_err(KeySourceError::Source)?;

        utils::openpgp::validate_keys(bytes, key_source.fingerprint)
            .map_err(KeySourceError::OpenPgp)
    }
}
