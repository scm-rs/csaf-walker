//! Discovering

use crate::model::metadata::{ProviderMetadata, TlpLabel};
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;
use url::Url;
use walker_common::utils::url::Urlify;

/// Discovery configuration
pub struct DiscoverConfig {
    /// The source to locate the provider metadata.
    ///
    /// This can be either a full path to a provider-metadata.json, or a base domain used by the
    /// CSAF metadata discovery process.
    pub source: String,

    /// Only report documents which have changed since the provided date. If a document has no
    /// change information, or this field is [`None`], it will always be reported.
    pub since: Option<SystemTime>,
}

impl DiscoverConfig {
    pub fn with_since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

impl From<&str> for DiscoverConfig {
    fn from(value: &str) -> Self {
        Self {
            since: None,
            source: value.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributionContext {
    Directory(Url),
    Feed { url: Url, tlp_label: TlpLabel },
}

impl DistributionContext {
    /// Get the URL of the distribution
    pub fn url(&self) -> &Url {
        match self {
            Self::Directory(url) => url,
            Self::Feed { url, .. } => url,
        }
    }

    /// Get the TLP label. Only ROLIE feeds carry one, directories are always [`TlpLabel::Unlabeled`].
    pub fn tlp_label(&self) -> TlpLabel {
        match self {
            Self::Directory(_) => TlpLabel::Unlabeled,
            Self::Feed { tlp_label, .. } => *tlp_label,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredAdvisory {
    /// A reference to the distribution and rolie information
    pub context: Arc<DistributionContext>,
    /// The URL of the advisory
    pub url: Url,
    /// The URL of the digest
    pub digest: Option<Url>,
    /// The URL of the signature
    pub signature: Option<Url>,
    /// The "last changed" date from the change information
    pub modified: SystemTime,
}

/// Get a document as [`DiscoveredAdvisory`]
pub trait AsDiscovered: Debug {
    fn as_discovered(&self) -> &DiscoveredAdvisory;
}

impl AsDiscovered for DiscoveredAdvisory {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        self
    }
}

impl Urlify for DiscoveredAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.context
            .url()
            .make_relative(&self.url)
            .map(|relative| (self.context.url(), relative))
    }
}

#[derive(Debug)]
pub struct DiscoveredContext<'c> {
    pub metadata: &'c ProviderMetadata,
}

/// Visiting discovered advisories
pub trait DiscoveredVisitor {
    type Error: std::fmt::Display + Debug;
    type Context;

    fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>>;

    fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<F, E, Fut> DiscoveredVisitor for F
where
    F: Fn(DiscoveredAdvisory) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display + Debug,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _ctx: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        self(advisory).await
    }
}
