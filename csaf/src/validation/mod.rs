//! Validation

use crate::{
    discover::{AsDiscovered, DiscoveredAdvisory},
    retrieve::{AsRetrieved, RetrievalContext, RetrievedAdvisory, RetrievedVisitor},
    source::Source,
};
use std::{
    fmt::{Debug, Display, Formatter},
    future::Future,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use url::Url;
use walker_common::{
    retrieve::RetrievalError,
    utils::{openpgp::PublicKey, url::Urlify},
    validate::{ValidationOptions, digest::validate_digest, openpgp},
};

/// A validated CSAF document
///
/// This includes
/// * The document could be retrieved
/// * The digest matches or was absent
/// * The signature was valid
#[derive(Clone, Debug)]
pub struct ValidatedAdvisory {
    /// The retrieved advisory
    pub retrieved: RetrievedAdvisory,
}

impl Urlify for ValidatedAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.retrieved.relative_base_and_url()
    }
}

impl Deref for ValidatedAdvisory {
    type Target = RetrievedAdvisory;

    fn deref(&self) -> &Self::Target {
        &self.retrieved
    }
}

impl DerefMut for ValidatedAdvisory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.retrieved
    }
}

impl AsDiscovered for ValidatedAdvisory {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        &self.discovered
    }
}

impl AsRetrieved for ValidatedAdvisory {
    fn as_retrieved(&self) -> &RetrievedAdvisory {
        &self.retrieved
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum ValidationError<S: Source> {
    Retrieval(RetrievalError<DiscoveredAdvisory, S>),
    DigestMismatch {
        expected: String,
        actual: String,
        retrieved: RetrievedAdvisory,
    },
    Signature {
        error: anyhow::Error,
        retrieved: RetrievedAdvisory,
    },
}

impl<S: Source + Debug> AsDiscovered for ValidationError<S> {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        match self {
            Self::Retrieval(err) => err.discovered(),
            Self::DigestMismatch { retrieved, .. } => retrieved.as_discovered(),
            Self::Signature { retrieved, .. } => retrieved.as_discovered(),
        }
    }
}

impl<S: Source> Urlify for ValidationError<S> {
    fn url(&self) -> &Url {
        match self {
            Self::Retrieval(err) => err.url(),
            Self::DigestMismatch { retrieved, .. } => &retrieved.url,
            Self::Signature { retrieved, .. } => &retrieved.url,
        }
    }
}

impl<S: Source> Display for ValidationError<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retrieval(err) => write!(f, "Retrieval error: {err}"),
            Self::DigestMismatch {
                expected,
                actual,
                retrieved: _,
            } => write!(
                f,
                "Digest mismatch - expected: {expected}, actual: {actual}",
            ),
            Self::Signature {
                error,
                retrieved: _,
            } => {
                write!(f, "Invalid signature: {error}",)
            }
        }
    }
}

pub struct ValidationContext<'c> {
    pub retrieval: &'c RetrievalContext<'c>,
}

impl<'c> Deref for ValidationContext<'c> {
    type Target = RetrievalContext<'c>;

    fn deref(&self) -> &Self::Target {
        self.retrieval
    }
}

pub trait ValidatedVisitor<S: Source> {
    type Error: Display + Debug;
    type Context;

    fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>>;

    fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<F, E, Fut, S> ValidatedVisitor<S> for F
where
    F: Fn(Result<ValidatedAdvisory, ValidationError<S>>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: Display + Debug,
    S: Source,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        self(result).await
    }
}

pub struct ValidationVisitor<V, S>
where
    V: ValidatedVisitor<S>,
    S: Source,
{
    visitor: V,
    options: ValidationOptions,
    _marker: PhantomData<S>,
}

#[allow(clippy::large_enum_variant)]
enum ValidationProcessError<S: Source> {
    /// Failed, but passing on to visitor
    Proceed(ValidationError<S>),
    /// Failed, aborting processing
    #[allow(unused)]
    Abort(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: Display + Debug,
{
    #[error("{0}")]
    Visitor(VE),
    #[error("Severe validation error: {0}")]
    Validation(anyhow::Error),
}

impl<V, S> ValidationVisitor<V, S>
where
    V: ValidatedVisitor<S>,
    S: Source,
{
    pub fn new(visitor: V) -> Self {
        Self {
            visitor,
            options: Default::default(),
            _marker: Default::default(),
        }
    }

    pub fn with_options(mut self, options: impl Into<ValidationOptions>) -> Self {
        self.options = options.into();
        self
    }

    /// Perform the actual validation.
    ///
    /// Returning either a processing error, or a result which will be forwarded to the visitor.
    async fn validate(
        &self,
        context: &InnerValidationContext<V::Context>,
        retrieved: RetrievedAdvisory,
    ) -> Result<ValidatedAdvisory, ValidationProcessError<S>> {
        if let Err((expected, actual)) = validate_digest(&retrieved.sha256) {
            return Err(ValidationProcessError::Proceed(
                ValidationError::DigestMismatch {
                    expected,
                    actual,
                    retrieved,
                },
            ));
        }
        if let Err((expected, actual)) = validate_digest(&retrieved.sha512) {
            return Err(ValidationProcessError::Proceed(
                ValidationError::DigestMismatch {
                    expected,
                    actual,
                    retrieved,
                },
            ));
        }

        if let Some(signature) = &retrieved.signature {
            match openpgp::validate_signature(
                &self.options,
                &context.keys,
                signature,
                &retrieved.data,
            ) {
                Ok(()) => Ok(ValidatedAdvisory { retrieved }),
                Err(error) => Err(ValidationProcessError::Proceed(
                    ValidationError::Signature { error, retrieved },
                )),
            }
        } else {
            Ok(ValidatedAdvisory { retrieved })
        }
    }
}

pub struct InnerValidationContext<VC> {
    context: VC,
    keys: Vec<PublicKey>,
}

impl<V, S> RetrievedVisitor<S> for ValidationVisitor<V, S>
where
    V: ValidatedVisitor<S>,
    S: Source,
{
    type Error = Error<V::Error>;
    type Context = InnerValidationContext<V::Context>;

    async fn visit_context(
        &self,
        context: &RetrievalContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        let keys = context.keys.clone();

        let context = self
            .visitor
            .visit_context(&ValidationContext { retrieval: context })
            .await
            .map_err(Error::Visitor)?;

        Ok(Self::Context { context, keys })
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        outcome: Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>,
    ) -> Result<(), Self::Error> {
        match outcome {
            Ok(advisory) => {
                let result = match self.validate(context, advisory).await {
                    Ok(result) => Ok(result),
                    Err(ValidationProcessError::Proceed(err)) => Err(err),
                    Err(ValidationProcessError::Abort(err)) => return Err(Error::Validation(err)),
                };
                self.visitor
                    .visit_advisory(&context.context, result)
                    .await
                    .map_err(Error::Visitor)?
            }
            Err(err) => self
                .visitor
                .visit_advisory(&context.context, Err(ValidationError::Retrieval(err)))
                .await
                .map_err(Error::Visitor)?,
        }

        Ok(())
    }
}
