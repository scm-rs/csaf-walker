use crate::{
    discover::{DiscoveredContext, DiscoveredSbom, DiscoveredVisitor},
    source::Source,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext},
};
use std::{
    fmt::{Debug, Display},
    path::PathBuf,
    time::SystemTime,
};
use tokio::fs;
use walker_common::{
    utils::{time::Human, url::Urlify},
    validate::ValidationError,
};

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

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        sbom: DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        let name = PathBuf::from(sbom.url.path());
        let name = name.file_name().ok_or(Error::Name)?;

        let path = self.output.join(name);

        if fs::try_exists(&path).await? {
            // if we have a "since", we use it as the file modification timestamp
            let file_modified = match self.since {
                Some(since) => since,
                None => fs::metadata(&path).await?.modified()?,
            };

            log::debug!(
                "Advisory modified: {}, file ({}) modified: {} ({:?})",
                Human(sbom.modified),
                name.to_string_lossy(),
                Human(file_modified),
                self.since.map(Human)
            );

            if file_modified >= sbom.modified {
                // the file was modified after the change date, skip it
                return Ok(());
            }
        }

        self.visitor
            .visit_sbom(context, sbom)
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

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        match (self.skip_failures, result) {
            (_, Ok(result)) => self.visitor.visit_sbom(context, Ok(result)).await,
            (false, Err(err)) => self.visitor.visit_sbom(context, Err(err)).await,
            (true, Err(err)) => {
                log::warn!("Skipping failed SBOM {}: {err}", err.url());
                Ok(())
            }
        }
    }
}
