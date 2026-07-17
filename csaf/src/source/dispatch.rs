use super::{HttpSourceError, Source};
use crate::discover::{DiscoveredAdvisory, DistributionContext};
use crate::model::metadata::ProviderMetadata;
use crate::retrieve::RetrievedAdvisory;
use crate::source::{FileSource, HttpSource};
#[cfg(feature = "openpgp")]
use walker_common::{
    utils::openpgp::PublicKey,
    validate::source::{Key, KeySource, KeySourceError, MapSourceError},
};

/// A common source type, dispatching to the known implementations.
///
/// This helps to create implementations which don't need to know the exact type. Unfortunately we
/// cannot just "box" this, as the [`Source`] needs to implement [`Clone`], which requires [`Sized`],
/// which prevents us from using `dyn` ("cannot be made into an object").
///
/// There may be a better way around this, feel free to send a PR ;-)
#[derive(Clone, Debug)]
pub enum DispatchSource {
    File(FileSource),
    Http(HttpSource),
}

impl From<FileSource> for DispatchSource {
    fn from(value: FileSource) -> Self {
        Self::File(value)
    }
}

impl From<HttpSource> for DispatchSource {
    fn from(value: HttpSource) -> Self {
        Self::Http(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchSourceError {
    #[error(transparent)]
    File(anyhow::Error),
    #[error(transparent)]
    Http(HttpSourceError),
}

impl walker_common::source::Source for DispatchSource {
    type Error = DispatchSourceError;
    type Retrieved = RetrievedAdvisory;
}

impl Source for DispatchSource {
    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        match self {
            Self::File(source) => source
                .load_metadata()
                .await
                .map_err(DispatchSourceError::File),
            Self::Http(source) => source
                .load_metadata()
                .await
                .map_err(DispatchSourceError::Http),
        }
    }

    async fn load_index(
        &self,
        context: DistributionContext,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error> {
        match self {
            Self::File(source) => source
                .load_index(context)
                .await
                .map_err(DispatchSourceError::File),
            Self::Http(source) => source
                .load_index(context)
                .await
                .map_err(DispatchSourceError::Http),
        }
    }

    async fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error> {
        match self {
            Self::File(source) => source
                .load_advisory(advisory)
                .await
                .map_err(DispatchSourceError::File),
            Self::Http(source) => source
                .load_advisory(advisory)
                .await
                .map_err(DispatchSourceError::Http),
        }
    }
}

#[cfg(feature = "openpgp")]
impl KeySource for DispatchSource {
    type Error = anyhow::Error;

    async fn load_public_key(
        &self,
        key: Key<'_>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        match self {
            Self::File(source) => source.load_public_key(key).await,
            Self::Http(source) => source
                .load_public_key(key)
                .await
                .map_source(|err| err.into()),
        }
    }
}
