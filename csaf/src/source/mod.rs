//! Sources

mod descriptor;
mod dispatch;
mod file;
mod http;

pub use descriptor::*;
pub use dispatch::*;
pub use file::*;
pub use http::*;

use crate::{
    discover::{DiscoverConfig, DiscoveredAdvisory, DistributionContext},
    model::metadata::ProviderMetadata,
    retrieve::RetrievedAdvisory,
};
use std::{fmt::Debug, future::Future, str::FromStr};
use walker_common::fetcher::FetcherOptions;

/// A source of CSAF documents
pub trait Source: walker_common::source::Source + Clone + Debug {
    fn load_metadata(&self) -> impl Future<Output = Result<ProviderMetadata, Self::Error>> + Send;

    fn load_index(
        &self,
        context: DistributionContext,
    ) -> impl Future<Output = Result<Vec<DiscoveredAdvisory>, Self::Error>> + Send;

    fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> impl Future<Output = Result<RetrievedAdvisory, Self::Error>> + Send;
}

/// A common way to create a new CSAF source.
pub async fn new_source(
    discover: impl Into<DiscoverConfig>,
    fetcher: impl Into<FetcherOptions>,
) -> anyhow::Result<DispatchSource> {
    let discover = discover.into();

    let descriptor = SourceDescriptor::from_str(&discover.source)?;
    descriptor.into_source(discover, fetcher.into()).await
}
