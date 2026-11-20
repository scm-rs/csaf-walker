//! Verification
//!
//! Checks to ensure conformity with the specification.

use crate::{
    check::Capped,
    discover::{AsDiscovered, DiscoveredAdvisory},
    retrieve::{AsRetrieved, RetrievalContext, RetrievedAdvisory, RetrievedVisitor},
    source::Source,
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
    verification::check::Check,
};
use csaf_rs::{
    csaf::raw::{HasParsed, RawDocument},
    json::JsonSource,
    schema::{
        csaf2_0::schema::CommonSecurityAdvisoryFramework as Csaf20,
        csaf2_1::schema::CommonSecurityAdvisoryFramework as Csaf21,
    },
};
use serde::de::{DeserializeOwned, Error as _};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    future::Future,
    hash::Hash,
    io::{self, ErrorKind},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use url::Url;
use walker_common::{retrieve::RetrievalError, utils::url::Urlify};

pub mod check;

/// Detect the CSAF version of a document, and convert it using the matching function.
fn detect<T, R>(
    data: T,
    v2_0: impl FnOnce(serde_json::Value) -> Result<R, io::Error>,
    v2_1: impl FnOnce(serde_json::Value) -> Result<R, io::Error>,
) -> Result<R, io::Error>
where
    T: JsonSource,
{
    use csaf_rs::csaf::loader::*;

    let VersionAndData { version, data } = detect_version_with(data)?;
    match &*version {
        "2.0" => v2_0(data),
        "2.1" => v2_1(data),
        _ => Err(io::Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported CSAF version: {version}"),
        )),
    }
}

/// Deserialize a document.
fn document<T>(data: serde_json::Value) -> Result<Box<T>, io::Error>
where
    T: DeserializeOwned,
{
    serde_json::from_value(data)
        .map(Box::new)
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))
}

/// Create a raw document, ensuring that it deserializes.
fn raw_document<T>(data: serde_json::Value) -> Result<Box<RawDocument<T>>, io::Error>
where
    T: DeserializeOwned,
{
    let document = RawDocument::new(data);
    if let Err(err) = document.get_parsed() {
        return Err(io::Error::new(ErrorKind::InvalidData, err.clone()));
    }
    Ok(Box::new(document))
}

/// A parsed CSAF document.
///
/// This only keeps the deserialized document. Use [`RawCsaf`] for validating a document.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Csaf {
    V2_0(Box<Csaf20>),
    V2_1(Box<Csaf21>),
}

impl Csaf {
    /// Parse a CSAF document.
    ///
    /// This fails if the document doesn't deserialize into the detected CSAF version.
    pub fn parse<T: JsonSource>(data: T) -> Result<Self, io::Error> {
        detect(
            data,
            |data| Ok(Self::V2_0(document(data)?)),
            |data| Ok(Self::V2_1(document(data)?)),
        )
    }

    /// Document level metadata.
    pub fn document(&self) -> DocumentLevelMetadata<'_> {
        match self {
            Self::V2_0(csaf) => DocumentLevelMetadata::V2_0(&csaf.document),
            Self::V2_1(csaf) => DocumentLevelMetadata::V2_1(&csaf.document),
        }
    }
}

/// A CSAF document, keeping its raw JSON.
///
/// Some csaf-rs tests (like the schema validation) only run on the raw JSON. So this is
/// required for validating a document. It keeps the raw JSON as well as the deserialized
/// document, so it requires more memory than [`Csaf`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RawCsaf {
    V2_0(Box<RawDocument<Csaf20>>),
    V2_1(Box<RawDocument<Csaf21>>),
}

impl RawCsaf {
    /// Parse a CSAF document.
    ///
    /// This fails if the document doesn't deserialize into the detected CSAF version.
    pub fn parse<T: JsonSource>(data: T) -> Result<Self, io::Error> {
        detect(
            data,
            |data| Ok(Self::V2_0(raw_document(data)?)),
            |data| Ok(Self::V2_1(raw_document(data)?)),
        )
    }

    /// Document level metadata.
    ///
    /// Returns `None` if the document doesn't deserialize. This can't happen for a [`RawCsaf`]
    /// created by [`RawCsaf::parse`].
    pub fn document(&self) -> Option<DocumentLevelMetadata<'_>> {
        Some(match self {
            Self::V2_0(csaf) => {
                DocumentLevelMetadata::V2_0(&csaf.get_parsed().as_ref().ok()?.document)
            }
            Self::V2_1(csaf) => {
                DocumentLevelMetadata::V2_1(&csaf.get_parsed().as_ref().ok()?.document)
            }
        })
    }
}

#[non_exhaustive]
pub enum DocumentLevelMetadata<'a> {
    V2_0(&'a csaf_rs::schema::csaf2_0::schema::DocumentLevelMetaData),
    V2_1(&'a csaf_rs::schema::csaf2_1::schema::DocumentLevelMetaData),
}

impl DocumentLevelMetadata<'_> {
    pub fn title(&self) -> &str {
        match self {
            Self::V2_0(csaf) => &csaf.title,
            Self::V2_1(csaf) => &csaf.title,
        }
    }

    pub fn tracking(&self) -> Tracking<'_> {
        match self {
            Self::V2_0(csaf) => Tracking::V2_0(&csaf.tracking),
            Self::V2_1(csaf) => Tracking::V2_1(&csaf.tracking),
        }
    }
}

#[non_exhaustive]
pub enum Tracking<'a> {
    V2_0(&'a csaf_rs::schema::csaf2_0::schema::Tracking),
    V2_1(&'a csaf_rs::schema::csaf2_1::schema::Tracking),
}

impl Tracking<'_> {
    pub fn id(&self) -> &str {
        match self {
            Self::V2_0(csaf) => &csaf.id,
            Self::V2_1(csaf) => &csaf.id,
        }
    }

    pub fn initial_release_date(&self) -> &str {
        match self {
            Self::V2_0(csaf) => &csaf.initial_release_date,
            Self::V2_1(csaf) => &csaf.initial_release_date,
        }
    }
}

#[derive(Debug)]
pub struct VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
{
    /// The advisory that was verified.
    pub advisory: A,
    /// The parsed CSAF document.
    pub csaf: RawCsaf,
    /// Per-check mandatory failures (errors).
    pub errors: HashMap<I, Capped>,
    /// Per-check optional/recommended failures (warnings).
    pub warnings: HashMap<I, Capped>,
    /// Per-check informational notes.
    pub infos: HashMap<I, Capped>,
    /// Checks that passed all tests.
    pub successes: HashSet<I>,
}

impl<A, I> Deref for VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
{
    type Target = A;

    fn deref(&self) -> &Self::Target {
        &self.advisory
    }
}

impl<A, I> DerefMut for VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.advisory
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError<UE, A>
where
    A: Debug,
    UE: Display + Debug,
{
    #[error(transparent)]
    Upstream(UE),
    #[error("document parsing error: {error}")]
    Parsing {
        advisory: A,
        error: serde_json::Error,
    },
    #[error("check runtime error: {error}")]
    Check { advisory: A, error: anyhow::Error },
}

impl<A, UE> AsDiscovered for VerificationError<UE, A>
where
    A: AsDiscovered + Debug,
    UE: AsDiscovered + Display + Debug,
{
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        match self {
            Self::Upstream(err) => err.as_discovered(),
            Self::Parsing { advisory, .. } => advisory.as_discovered(),
            Self::Check { advisory, .. } => advisory.as_discovered(),
        }
    }
}

impl<UE, A> Urlify for VerificationError<UE, A>
where
    A: AsRetrieved + Debug,
    UE: Urlify + Display + Debug,
{
    fn url(&self) -> &Url {
        match self {
            Self::Upstream(err) => err.url(),
            Self::Parsing { advisory, .. } => advisory.as_retrieved().url(),
            Self::Check { advisory, .. } => advisory.as_retrieved().url(),
        }
    }
}

pub struct VerificationContext {}

/// A visitor accepting a verified advisory
pub trait VerifiedVisitor<A, E, I>: Send + Sync
where
    A: AsRetrieved,
    E: Display + Debug + Send,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
{
    type Error: Display + Debug + Send;
    type Context: Send + Sync;

    fn visit_context(
        &self,
        context: &VerificationContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>> + Send;

    fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<VerifiedAdvisory<A, I>, VerificationError<E, A>>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: Display + Debug,
{
    #[error(transparent)]
    Visitor(VE),
}

/// A visitor implementing the verification of a CSAF document
pub struct VerifyingVisitor<A, E, V, I>
where
    A: AsRetrieved,
    V: VerifiedVisitor<A, E, I>,
    E: Display + Debug + Send,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
{
    visitor: V,
    checks: Vec<(I, Box<dyn Check>)>,
    _marker: PhantomData<fn() -> (A, E)>,
}

impl<A, E, V, I> VerifyingVisitor<A, E, V, I>
where
    A: AsRetrieved,
    V: VerifiedVisitor<A, E, I>,
    E: Display + Debug + Send,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
{
    pub fn new(visitor: V) -> Self {
        Self {
            visitor,
            checks: vec![],
            _marker: Default::default(),
        }
    }

    pub fn with_checks(visitor: V, checks: Vec<(I, Box<dyn Check>)>) -> Self {
        Self {
            visitor,
            checks,
            _marker: Default::default(),
        }
    }

    pub fn add<F: Check + 'static>(mut self, index: I, check: F) -> Self {
        self.checks.push((index, Box::new(check)));
        self
    }

    async fn verify(&self, advisory: A) -> Result<VerifiedAdvisory<A, I>, VerificationError<E, A>> {
        let data = advisory.as_retrieved().data.clone();

        let csaf = match tokio::task::spawn_blocking(move || RawCsaf::parse(&*data)).await {
            Ok(Ok(csaf)) => csaf,
            Ok(Err(error)) => {
                return Err(VerificationError::Parsing {
                    error: serde::de::Error::custom(error),
                    advisory,
                });
            }
            Err(_) => {
                return Err(VerificationError::Parsing {
                    error: serde_json::error::Error::custom("failed to wait for deserialization"),
                    advisory,
                });
            }
        };

        let mut errors = HashMap::new();
        let mut warnings = HashMap::new();
        let mut infos = HashMap::new();
        let mut successes = HashSet::new();

        for (index, check) in &self.checks {
            let result = match check.as_ref().check(&csaf).await {
                Ok(result) => result,
                Err(error) => return Err(VerificationError::Check { error, advisory }),
            };
            if result.is_ok() {
                successes.insert(index.clone());
            } else {
                errors.insert(index.clone(), result.errors);
                warnings.insert(index.clone(), result.warnings);
                infos.insert(index.clone(), result.infos);
            }
        }

        Ok(VerifiedAdvisory {
            advisory,
            csaf,
            errors,
            warnings,
            infos,
            successes,
        })
    }
}

impl<V, I, S> RetrievedVisitor<S>
    for VerifyingVisitor<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>, V, I>
where
    V: VerifiedVisitor<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>, I>,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
    S: Source,
{
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        _context: &RetrievalContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(&VerificationContext {})
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>,
    ) -> Result<(), Self::Error> {
        let result = match result {
            Ok(doc) => self.verify(doc).await,
            Err(err) => Err(VerificationError::Upstream(err)),
        };

        self.visitor
            .visit_advisory(context, result)
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}

impl<V, I, S> ValidatedVisitor<S> for VerifyingVisitor<ValidatedAdvisory, ValidationError<S>, V, I>
where
    V: VerifiedVisitor<ValidatedAdvisory, ValidationError<S>, I>,
    I: Clone + PartialEq + Eq + Hash + Send + Sync,
    S: Source,
{
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        _context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(&VerificationContext {})
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        let result = match result {
            Ok(doc) => self.verify(doc).await,
            Err(err) => Err(VerificationError::Upstream(err)),
        };

        self.visitor
            .visit_advisory(context, result)
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}

impl<F, E, Fut, A, I, UE> VerifiedVisitor<A, UE, I> for F
where
    UE: Debug + Display + Send + 'static,
    F: Fn(Result<VerifiedAdvisory<A, I>, VerificationError<UE, A>>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), E>> + Send,
    E: Display + Debug + 'static + Send,
    A: AsRetrieved + 'static,
    I: Clone + PartialEq + Eq + Hash + Send + Sync + 'static,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &VerificationContext,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _ctx: &Self::Context,
        outcome: Result<VerifiedAdvisory<A, I>, VerificationError<UE, A>>,
    ) -> Result<(), Self::Error> {
        self(outcome).await
    }
}
