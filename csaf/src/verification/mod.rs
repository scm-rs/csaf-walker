//! Verification
//!
//! Checks to ensure conformity with the specification.

use crate::{
    discover::{AsDiscovered, DiscoveredAdvisory},
    retrieve::{AsRetrieved, RetrievalContext, RetrievedAdvisory, RetrievedVisitor},
    source::Source,
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
    verification::check::{Check, CheckError},
};
use csaf::Csaf;
use serde::de::Error as _;
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    future::Future,
    hash::Hash,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use url::Url;
use walker_common::{retrieve::RetrievalError, utils::url::Urlify};

pub mod check;

#[derive(Debug)]
pub struct VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash,
{
    pub advisory: A,
    pub csaf: Csaf,
    pub failures: HashMap<I, Vec<CheckError>>,
    pub successes: HashSet<I>,
}

impl<A, I> Deref for VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash,
{
    type Target = A;

    fn deref(&self) -> &Self::Target {
        &self.advisory
    }
}

impl<A, I> DerefMut for VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash,
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
pub trait VerifiedVisitor<A, E, I>
where
    A: AsRetrieved,
    E: Display + Debug,
    I: Clone + PartialEq + Eq + Hash,
{
    type Error: Display + Debug;
    type Context;

    fn visit_context(
        &self,
        context: &VerificationContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>>;

    fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<VerifiedAdvisory<A, I>, VerificationError<E, A>>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
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
    E: Display + Debug,
    I: Clone + PartialEq + Eq + Hash,
{
    visitor: V,
    checks: Vec<(I, Box<dyn Check>)>,
    _marker: PhantomData<(A, E)>,
}

impl<A, E, V, I> VerifyingVisitor<A, E, V, I>
where
    A: AsRetrieved,
    V: VerifiedVisitor<A, E, I>,
    E: Display + Debug,
    I: Clone + PartialEq + Eq + Hash,
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

        let csaf = match tokio::task::spawn_blocking(move || serde_json::from_slice::<Csaf>(&data))
            .await
        {
            Ok(Ok(csaf)) => csaf,
            Ok(Err(error)) => return Err(VerificationError::Parsing { error, advisory }),
            Err(_) => {
                return Err(VerificationError::Parsing {
                    error: serde_json::error::Error::custom("failed to wait for deserialization"),
                    advisory,
                });
            }
        };

        let mut failures = HashMap::new();
        let mut successes = HashSet::new();

        for (index, check) in &self.checks {
            let result = match check.as_ref().check(&csaf).await {
                Ok(result) => result,
                Err(error) => return Err(VerificationError::Check { error, advisory }),
            };
            if !result.is_empty() {
                failures.insert(index.clone(), result);
            } else {
                successes.insert(index.clone());
            }
        }

        Ok(VerifiedAdvisory {
            advisory,
            csaf,
            failures,
            successes,
        })
    }
}

impl<V, I, S> RetrievedVisitor<S>
    for VerifyingVisitor<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>, V, I>
where
    V: VerifiedVisitor<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>, I>,
    I: Clone + PartialEq + Eq + Hash,
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
    I: Clone + PartialEq + Eq + Hash,
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
    UE: Debug + Display + 'static,
    F: Fn(Result<VerifiedAdvisory<A, I>, VerificationError<UE, A>>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: Display + Debug + 'static,
    A: AsRetrieved + 'static,
    I: Clone + PartialEq + Eq + Hash + 'static,
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
