//! The actual walker

use crate::{
    discover::{DiscoveredContext, DiscoveredVisitor},
    source::Source,
};
use futures::{StreamExt, TryFutureExt, TryStreamExt, stream};
use std::{fmt::Debug, sync::Arc};
use url::ParseError;
use walker_common::progress::{Progress, ProgressBar};

#[derive(Debug, thiserror::Error)]
pub enum Error<VE, SE>
where
    VE: std::fmt::Display + Debug,
    SE: std::fmt::Display + Debug,
{
    #[error("Source error: {0}")]
    Source(SE),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("Visitor error: {0}")]
    Visitor(VE),
}

pub struct Walker<S: Source, P: Progress> {
    source: S,
    progress: P,
}

impl<S: Source> Walker<S, ()> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            progress: (),
        }
    }
}

impl<S: Source, P: Progress> Walker<S, P> {
    pub fn with_progress<U: Progress>(self, progress: U) -> Walker<S, U> {
        Walker {
            source: self.source,
            progress,
        }
    }

    pub async fn walk<V>(self, visitor: V) -> Result<(), Error<V::Error, S::Error>>
    where
        V: DiscoveredVisitor,
    {
        let metadata = self.source.load_metadata().await.map_err(Error::Source)?;

        let context = visitor
            .visit_context(&DiscoveredContext {
                metadata: &metadata,
            })
            .await
            .map_err(Error::Visitor)?;

        let index = self.source.load_index().await.map_err(Error::Source)?;
        let mut progress = self.progress.start(index.len());

        for sbom in index {
            log::debug!("  Discovered SBOM: {sbom:?}");
            progress
                .set_message(
                    sbom.url
                        .path()
                        .rsplit_once('/')
                        .map(|(_, s)| s)
                        .unwrap_or(sbom.url.as_str())
                        .to_string(),
                )
                .await;
            visitor
                .visit_sbom(&context, sbom)
                .await
                .map_err(Error::Visitor)?;
            progress.tick().await;
        }

        progress.finish().await;

        Ok(())
    }

    pub async fn walk_parallel<V>(
        self,
        limit: usize,
        visitor: V,
    ) -> Result<(), Error<V::Error, S::Error>>
    where
        V: DiscoveredVisitor,
    {
        log::debug!("Running {limit} workers");

        let metadata = self.source.load_metadata().await.map_err(Error::Source)?;
        let context = visitor
            .visit_context(&DiscoveredContext {
                metadata: &metadata,
            })
            .await
            .map_err(Error::Visitor)?;

        let visitor = Arc::new(visitor);
        let context = Arc::new(context);

        stream::iter(self.source.load_index().await.map_err(Error::Source)?)
            .map(Ok)
            .try_for_each_concurrent(limit, async |sbom| {
                log::debug!("Discovered advisory: {}", sbom.url);

                visitor
                    .visit_sbom(&context, sbom)
                    .map_err(Error::Visitor)
                    .await
            })
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod send_test {
    use super::*;

    fn assert_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn walk_is_send<S: Source, P: Progress, V: DiscoveredVisitor>(
        walker: Walker<S, P>,
        visitor: V,
    ) {
        assert_send(walker.walk(visitor));
    }

    #[allow(dead_code)]
    fn walk_parallel_is_send<S: Source, P: Progress, V: DiscoveredVisitor>(
        walker: Walker<S, P>,
        visitor: V,
    ) {
        assert_send(walker.walk_parallel(4, visitor));
    }
}
