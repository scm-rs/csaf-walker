//! Validation

use crate::{
    discover::DiscoveredSbom,
    retrieve::{RetrievalContext, RetrievedSbom, RetrievedVisitor},
    source::Source,
};
use std::{
    fmt::{Debug, Display},
    future::Future,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use url::Url;
use walker_common::{
    retrieve::RetrievalError,
    utils::{openpgp::PublicKey, url::Urlify},
    validate::{ValidationError, ValidationOptions, digest::validate_digest, openpgp},
};

#[derive(Clone, Debug)]
pub struct ValidatedSbom {
    /// The discovered advisory
    pub retrieved: RetrievedSbom,
}

impl Urlify for ValidatedSbom {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.retrieved.relative_base_and_url()
    }
}

impl Deref for ValidatedSbom {
    type Target = RetrievedSbom;

    fn deref(&self) -> &Self::Target {
        &self.retrieved
    }
}

impl DerefMut for ValidatedSbom {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.retrieved
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

    fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<S>>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<F, E, Fut, S> ValidatedVisitor<S> for F
where
    F: Fn(Result<ValidatedSbom, ValidationError<S>>) -> Fut,
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

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<S>>,
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

enum ValidationProcessError<S: Source> {
    /// Failed, but passing on to visitor
    Proceed(Box<ValidationError<S>>),
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
    S: Source<Retrieved = RetrievedSbom>,
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
        retrieved: RetrievedSbom,
    ) -> Result<ValidatedSbom, ValidationProcessError<S>> {
        if let Err((expected, actual)) = validate_digest(&retrieved.sha256) {
            return Err(ValidationProcessError::Proceed(Box::new(
                ValidationError::DigestMismatch {
                    expected,
                    actual,
                    retrieved,
                },
            )));
        }
        if let Err((expected, actual)) = validate_digest(&retrieved.sha512) {
            return Err(ValidationProcessError::Proceed(Box::new(
                ValidationError::DigestMismatch {
                    expected,
                    actual,
                    retrieved,
                },
            )));
        }

        if let Some(signature) = &retrieved.signature {
            match openpgp::validate_signature(
                &self.options,
                &context.keys,
                signature,
                &retrieved.data,
            ) {
                Ok(()) => Ok(ValidatedSbom { retrieved }),
                Err(error) => Err(ValidationProcessError::Proceed(Box::new(
                    ValidationError::Signature { error, retrieved },
                ))),
            }
        } else {
            Ok(ValidatedSbom { retrieved })
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
    S: Source<Retrieved = RetrievedSbom>,
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

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        outcome: Result<RetrievedSbom, RetrievalError<DiscoveredSbom, S>>,
    ) -> Result<(), Self::Error> {
        match outcome {
            Ok(advisory) => {
                let result = match self.validate(context, advisory).await {
                    Ok(result) => Ok(result),
                    Err(ValidationProcessError::Proceed(err)) => Err(*err),
                    Err(ValidationProcessError::Abort(err)) => return Err(Error::Validation(err)),
                };
                self.visitor
                    .visit_sbom(&context.context, result)
                    .await
                    .map_err(Error::Visitor)?
            }
            Err(err) => self
                .visitor
                .visit_sbom(&context.context, Err(ValidationError::Retrieval(err)))
                .await
                .map_err(Error::Visitor)?,
        }

        Ok(())
    }
}
