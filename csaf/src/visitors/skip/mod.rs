use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use crate::model::store::distribution_base;
use crate::source::Source;
use crate::validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError};
use std::fmt::{Debug, Display};
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::fs;
use walker_common::utils::{time::Human, url::Urlify};

#[derive(Debug, thiserror::Error)]
pub enum Error<VE: Display + Debug> {
    #[error("{0}")]
    Visitor(VE),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unable to get name from URL")]
    Name,
}

/// A visitor, skipping advisories for existing files.
pub struct SkipExistingVisitor<V: DiscoveredVisitor> {
    pub visitor: V,
    pub output: PathBuf,
    /// The time "since" when we consider changes "new"
    ///
    /// Overrides the "file modified" timestamp which is used by default.
    pub since: Option<SystemTime>,
}

impl<V: DiscoveredVisitor> DiscoveredVisitor for SkipExistingVisitor<V> {
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(context)
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        let name = match advisory.context.url().clone().make_relative(&advisory.url) {
            Some(name) => name,
            None => return Err(Error::Name),
        };
        let path = distribution_base(&self.output, advisory.context.url().as_str()).join(&name);

        if fs::try_exists(&path).await? {
            // if we have a "since", we use it as the file modification timestamp
            let file_modified = match self.since {
                Some(since) => since,
                None => fs::metadata(&path).await?.modified()?,
            };

            log::debug!(
                "Advisory modified: {}, file ({}) modified: {} ({:?})",
                Human(advisory.modified),
                name,
                Human(file_modified),
                self.since.map(Human)
            );

            if file_modified >= advisory.modified {
                // the file was modified after the change date, skip it
                return Ok(());
            }
        } else {
            log::debug!("File did not exist: {}", path.display());
        }

        self.visitor
            .visit_advisory(context, advisory)
            .await
            .map_err(Error::Visitor)
    }
}

/// A visitor which will skip (with a warning) any failed document.
pub struct SkipFailedVisitor<V> {
    pub visitor: V,
    pub skip_failures: bool,
}

impl<V> SkipFailedVisitor<V> {
    pub fn new(visitor: V) -> Self {
        Self {
            visitor,
            skip_failures: true,
        }
    }
}

impl<V: ValidatedVisitor<S>, S: Source> ValidatedVisitor<S> for SkipFailedVisitor<V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        match (self.skip_failures, result) {
            (_, Ok(result)) => self.visitor.visit_advisory(context, Ok(result)).await,
            (false, Err(err)) => self.visitor.visit_advisory(context, Err(err)).await,
            (true, Err(err)) => {
                log::warn!("Skipping failed advisory ({}): {err}", err.url());
                Ok(())
            }
        }
    }
}
