//! Discovering

use crate::{model::metadata, model::metadata::SourceMetadata};
use std::{fmt::Debug, future::Future, ops::Deref, time::SystemTime};
use url::Url;
use walker_common::utils::url::Urlify;

/// Discovery configuration
pub struct DiscoverConfig {
    /// The URL to locate the SBOM metadata.
    pub source: String,

    /// Only report documents which have changed since the provided date. If a document has no
    /// change information, or this field is [`None`], it wil always be reported.
    pub since: Option<SystemTime>,

    /// Keys which can be used for validation
    pub keys: Vec<metadata::Key>,
}

impl DiscoverConfig {
    pub fn with_since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredSbom {
    /// The URL of the SBOM
    pub url: Url,
    /// The "last changed" date from the change information
    pub modified: SystemTime,
}

impl Urlify for DiscoveredSbom {
    fn url(&self) -> &Url {
        &self.url
    }
}

#[derive(Debug)]
pub struct DiscoveredContext<'c> {
    pub metadata: &'c SourceMetadata,
}

impl Deref for DiscoveredContext<'_> {
    type Target = SourceMetadata;

    fn deref(&self) -> &Self::Target {
        self.metadata
    }
}

/// Visiting discovered SBOMs
pub trait DiscoveredVisitor: Send + Sync {
    type Error: std::fmt::Display + Debug + Send;
    type Context: Send + Sync;

    fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>> + Send;

    fn visit_sbom(
        &self,
        context: &Self::Context,
        sbom: DiscoveredSbom,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<F, E, Fut> DiscoveredVisitor for F
where
    F: Fn(DiscoveredSbom) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), E>> + Send,
    E: std::fmt::Display + Debug + Send,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        sbom: DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        self(sbom).await
    }
}
