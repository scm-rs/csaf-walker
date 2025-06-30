//! Retrieval

use crate::{
    discover::{DiscoveredContext, DiscoveredSbom, DiscoveredVisitor},
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
    utils::{openpgp::PublicKey, url::Urlify},
    validate::source::{KeySource, KeySourceError},
};

/// A retrieved (but unverified) SBOM
#[derive(Clone, Debug)]
pub struct RetrievedSbom {
    /// The discovered advisory
    pub discovered: DiscoveredSbom,

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

impl Urlify for RetrievedSbom {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.discovered.relative_base_and_url()
    }
}

impl Deref for RetrievedSbom {
    type Target = DiscoveredSbom;

    fn deref(&self) -> &Self::Target {
        &self.discovered
    }
}

impl DerefMut for RetrievedSbom {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.discovered
    }
}

impl RetrievedDocument for RetrievedSbom {
    type Discovered = DiscoveredSbom;
}

pub struct RetrievalContext<'c> {
    pub discovered: &'c DiscoveredContext<'c>,
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

    fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<RetrievedSbom, RetrievalError<DiscoveredSbom, S>>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<F, E, Fut, S> RetrievedVisitor<S> for F
where
    F: Fn(Result<RetrievedSbom, RetrievalError<DiscoveredSbom, S>>) -> Fut,
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

    async fn visit_sbom(
        &self,
        _ctx: &Self::Context,
        outcome: Result<RetrievedSbom, RetrievalError<DiscoveredSbom, S>>,
    ) -> Result<(), Self::Error> {
        self(outcome).await
    }
}

pub struct RetrievingVisitor<V: RetrievedVisitor<S>, S: Source + KeySource> {
    visitor: V,
    source: S,
}

impl<V, S> RetrievingVisitor<V, S>
where
    V: RetrievedVisitor<S>,
    S: Source + KeySource,
{
    pub fn new(source: S, visitor: V) -> Self {
        Self { visitor, source }
    }
}

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
        let mut keys = Vec::with_capacity(context.metadata.keys.len());

        for key in &context.metadata.keys {
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
                keys: &keys,
                discovered: context,
            })
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        discovered: DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        let sbom = self
            .source
            .load_sbom(discovered.clone())
            .await
            .map_err(|err| RetrievalError::Source { err, discovered });

        self.visitor
            .visit_sbom(context, sbom)
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}
