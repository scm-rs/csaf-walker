//! Retrieval

use crate::{
    discover::{AsDiscovered, DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor},
    source::Source,
};
use bytes::Bytes;
use sha2::{Sha256, Sha512};
use std::{
    fmt::Debug,
    future::Future,
    ops::{Deref, DerefMut},
};
use url::Url;
use walker_common::{
    retrieve::{RetrievalError, RetrievalMetadata, RetrievedDigest, RetrievedDocument},
    utils::url::Urlify,
};

#[cfg(feature = "openpgp")]
use walker_common::{
    utils::openpgp::PublicKey,
    validate::source::{KeySource, KeySourceError},
};

/// A retrieved (but unverified) advisory
#[derive(Clone, Debug)]
pub struct RetrievedAdvisory {
    /// The discovered advisory
    pub discovered: DiscoveredAdvisory,

    /// The advisory data
    pub data: Bytes,
    /// Signature data
    pub signature: Option<String>,

    /// SHA-256 digest
    pub sha256: Option<RetrievedDigest<Sha256>>,
    /// SHA-512 digest
    pub sha512: Option<RetrievedDigest<Sha512>>,

    /// Metadata from the retrieval process
    pub metadata: RetrievalMetadata,
}

impl Urlify for RetrievedAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.discovered.relative_base_and_url()
    }
}

/// Get a document as [`RetrievedAdvisory`]
pub trait AsRetrieved: Debug {
    fn as_retrieved(&self) -> &RetrievedAdvisory;
}

impl AsDiscovered for RetrievedAdvisory {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        &self.discovered
    }
}

impl AsRetrieved for RetrievedAdvisory {
    fn as_retrieved(&self) -> &RetrievedAdvisory {
        self
    }
}

impl Deref for RetrievedAdvisory {
    type Target = DiscoveredAdvisory;

    fn deref(&self) -> &Self::Target {
        &self.discovered
    }
}

impl DerefMut for RetrievedAdvisory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.discovered
    }
}

impl RetrievedDocument for RetrievedAdvisory {
    type Discovered = DiscoveredAdvisory;
}

pub struct RetrievalContext<'c> {
    pub discovered: &'c DiscoveredContext<'c>,
    #[cfg(feature = "openpgp")]
    pub keys: &'c Vec<PublicKey>,
}

impl<'c> Deref for RetrievalContext<'c> {
    type Target = DiscoveredContext<'c>;

    fn deref(&self) -> &Self::Target {
        self.discovered
    }
}

pub trait RetrievedVisitor<S: Source> {
    type Error: std::fmt::Display + Debug;
    type Context;

    fn visit_context(
        &self,
        context: &RetrievalContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>>;

    fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<F, E, Fut, S> RetrievedVisitor<S> for F
where
    F: Fn(Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display + Debug,
    S: Source,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &RetrievalContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _ctx: &Self::Context,
        outcome: Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>,
    ) -> Result<(), Self::Error> {
        self(outcome).await
    }
}

pub struct RetrievingVisitor<V: RetrievedVisitor<S>, S: Source> {
    visitor: V,
    source: S,
}

impl<V, S> RetrievingVisitor<V, S>
where
    V: RetrievedVisitor<S>,
    S: Source,
{
    pub fn new(source: S, visitor: V) -> Self {
        Self { visitor, source }
    }

    /// Load a single advisory and hand the outcome over to the wrapped visitor.
    async fn load_and_visit(
        &self,
        context: &V::Context,
        discovered: DiscoveredAdvisory,
    ) -> Result<(), V::Error> {
        let advisory = self
            .source
            .load_advisory(discovered.clone())
            .await
            .map_err(|err| RetrievalError::Source { err, discovered });

        self.visitor.visit_advisory(context, advisory).await
    }
}

/// An error from the [`RetrievingVisitor`].
///
/// With the `openpgp` feature disabled, this type has no `KSE` (key source
/// error) parameter and no `KeySource` variant.
#[cfg(feature = "openpgp")]
#[derive(Debug, thiserror::Error)]
pub enum Error<VE, SE, KSE>
where
    VE: std::fmt::Display + Debug,
    SE: std::fmt::Display + Debug,
    KSE: std::fmt::Display + Debug,
{
    #[error("Source error: {0}")]
    Source(SE),
    #[error("Key source error: {0}")]
    KeySource(KeySourceError<KSE>),
    #[error(transparent)]
    Visitor(VE),
}

/// An error from the [`RetrievingVisitor`].
///
/// With the `openpgp` feature enabled, this type has an additional `KSE` (key
/// source error) parameter and a `KeySource` variant.
#[cfg(not(feature = "openpgp"))]
#[derive(Debug, thiserror::Error)]
pub enum Error<VE, SE>
where
    VE: std::fmt::Display + Debug,
    SE: std::fmt::Display + Debug,
{
    #[error("Source error: {0}")]
    Source(SE),
    #[error(transparent)]
    Visitor(VE),
}

#[cfg(feature = "openpgp")]
impl<V, S> DiscoveredVisitor for RetrievingVisitor<V, S>
where
    V: RetrievedVisitor<S>,
    S: Source + KeySource,
{
    type Error =
        Error<V::Error, <S as walker_common::source::Source>::Error, <S as KeySource>::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        let mut keys = Vec::with_capacity(context.metadata.public_openpgp_keys.len());

        for key in &context.metadata.public_openpgp_keys {
            keys.push(
                self.source
                    .load_public_key(key.into())
                    .await
                    .map_err(Error::KeySource)?,
            );
        }

        log::info!(
            "Loaded {} public key{}",
            keys.len(),
            if keys.len() != 1 {
                "s"
            } else {
                Default::default()
            }
        );
        if log::log_enabled!(log::Level::Debug) {
            for key in keys.iter().flat_map(|k| &k.certs) {
                log::debug!("   {}", key.key_handle());
                for id in key.userids() {
                    log::debug!("     {}", id.userid());
                }
            }
        }

        self.visitor
            .visit_context(&RetrievalContext {
                discovered: context,
                keys: &keys,
            })
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        discovered: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        self.load_and_visit(context, discovered)
            .await
            .map_err(Error::Visitor)
    }
}

#[cfg(not(feature = "openpgp"))]
impl<V, S> DiscoveredVisitor for RetrievingVisitor<V, S>
where
    V: RetrievedVisitor<S>,
    S: Source,
{
    type Error = Error<V::Error, <S as walker_common::source::Source>::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(&RetrievalContext {
                discovered: context,
            })
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        discovered: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        self.load_and_visit(context, discovered)
            .await
            .map_err(Error::Visitor)
    }
}
