use super::*;
use crate::csaf::{
    retrieve::{RetrievalContext, RetrievedAdvisory, RetrievedVisitor},
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use csaf_walker::{discover::DiscoveredAdvisory, source::Source};
use walker_common::retrieve::RetrievalError;

#[derive(Debug, thiserror::Error)]
pub enum SendRetrievedAdvisoryError<S: Source> {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError<DiscoveredAdvisory, S>),
}

impl<S: Source> RetrievedVisitor<S> for SendVisitor {
    type Error = SendRetrievedAdvisoryError<S>;
    type Context = ();

    async fn visit_context(&self, _: &RetrievalContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>,
    ) -> Result<(), Self::Error> {
        self.send_retrieved_advisory(result?).await?;
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum SendValidatedAdvisoryError<S: Source> {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Validation(#[from] ValidationError<S>),
}

impl<S: Source> ValidatedVisitor<S> for SendVisitor {
    type Error = SendValidatedAdvisoryError<S>;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        self.send_retrieved_advisory(result?.retrieved).await?;
        Ok(())
    }
}

impl SendVisitor {
    async fn send_retrieved_advisory(&self, advisory: RetrievedAdvisory) -> Result<(), SendError> {
        log::debug!(
            "Sending: {} (modified: {:?})",
            advisory.url,
            advisory.metadata.last_modification
        );

        let RetrievedAdvisory {
            data,
            discovered: DiscoveredAdvisory { url, .. },
            ..
        } = advisory;

        self.send_json(url.as_str(), data).await
    }

    pub async fn send_json(&self, name: &str, data: Bytes) -> Result<(), SendError> {
        self.send(name, data, |request| {
            request.header(header::CONTENT_TYPE, "application/json")
        })
        .await
    }
}
