//! The actual walker

use crate::{
    discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor, DistributionContext},
    model::metadata::{Distribution, TlpLabel},
    source::Source,
};
use futures::{Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt, stream};
use std::{collections::HashSet, fmt::Debug, ops::RangeBounds, sync::Arc};
use tokio::sync::Mutex;
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

pub type DistributionFilter = Box<dyn Fn(&DistributionContext) -> bool + Send + Sync>;

/// Handles errors that occur when fetching a distribution's index.
///
/// Return `Ok(())` to skip the distribution and continue walking.
/// Return `Err(e)` to abort the walk with the error.
pub trait DistributionErrorHandler<E>: Send + Sync {
    fn handle(&self, ctx: &DistributionContext, error: E) -> Result<(), E>;
}

impl<E> DistributionErrorHandler<E> for () {
    fn handle(&self, _ctx: &DistributionContext, error: E) -> Result<(), E> {
        Err(error)
    }
}

impl<F, E> DistributionErrorHandler<E> for F
where
    F: Fn(&DistributionContext, E) -> Result<(), E> + Send + Sync,
{
    fn handle(&self, ctx: &DistributionContext, error: E) -> Result<(), E> {
        (self)(ctx, error)
    }
}

/// Filters distributions by their TLP label.
///
/// Returns `true` to include the distribution, `false` to skip it.
pub trait TlpFilter: Send + Sync {
    fn include(&self, label: &TlpLabel) -> bool;
}

impl TlpFilter for HashSet<TlpLabel> {
    fn include(&self, label: &TlpLabel) -> bool {
        self.contains(label)
    }
}

impl<F> TlpFilter for F
where
    F: Fn(&TlpLabel) -> bool + Send + Sync,
{
    fn include(&self, label: &TlpLabel) -> bool {
        (self)(label)
    }
}

impl TlpFilter for Box<dyn TlpFilter> {
    fn include(&self, label: &TlpLabel) -> bool {
        (**self).include(label)
    }
}

macro_rules! impl_tlp_filter_for_range {
    ($($range:ty),* $(,)?) => {
        $(
            impl TlpFilter for $range {
                fn include(&self, label: &TlpLabel) -> bool {
                    !RangeBounds::contains(self, label)
                }
            }
        )*
    };
}

impl_tlp_filter_for_range!(
    std::ops::Range<TlpLabel>,
    std::ops::RangeFrom<TlpLabel>,
    std::ops::RangeTo<TlpLabel>,
    std::ops::RangeInclusive<TlpLabel>,
    std::ops::RangeToInclusive<TlpLabel>,
    std::ops::RangeFull,
);

/// Configuration for how distributions are collected and filtered.
#[derive(Default)]
pub struct DistributionConfig {
    pub tlp_filter: Option<Box<dyn TlpFilter>>,
}

impl DistributionConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tlp_filter(mut self, filter: impl TlpFilter + 'static) -> Self {
        self.tlp_filter = Some(Box::new(filter));
        self
    }
}

pub struct Walker<S: Source, P: Progress> {
    source: S,
    progress: P,
    distribution_filter: Option<DistributionFilter>,
    distribution_error_handler: Box<dyn DistributionErrorHandler<S::Error>>,
    tlp_filter: Option<Box<dyn TlpFilter>>,
}

impl<S: Source> Walker<S, ()> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            progress: (),
            distribution_filter: None,
            distribution_error_handler: Box::new(()),
            tlp_filter: None,
        }
    }
}

impl<S: Source, P: Progress> Walker<S, P> {
    pub fn with_progress<U: Progress>(self, progress: U) -> Walker<S, U> {
        Walker {
            progress,
            source: self.source,
            distribution_filter: self.distribution_filter,
            distribution_error_handler: self.distribution_error_handler,
            tlp_filter: self.tlp_filter,
        }
    }

    /// Set a filter for distributions.
    ///
    /// Each distribution from the metadata file will be passed to this function, if it returns `false`, the distribution
    /// will not even be fetched.
    pub fn with_distribution_filter<F>(mut self, distribution_filter: F) -> Self
    where
        F: Fn(&DistributionContext) -> bool + Send + Sync + 'static,
    {
        self.distribution_filter = Some(Box::new(distribution_filter));
        self
    }

    /// Set a handler for errors that occur when fetching a distribution's index.
    ///
    /// When a distribution fetch fails, the handler decides whether to skip it (return `Ok(())`)
    /// or abort the walk (return `Err`). The default handler aborts on any error.
    pub fn with_distribution_error_handler(
        mut self,
        handler: impl DistributionErrorHandler<S::Error> + 'static,
    ) -> Self {
        self.distribution_error_handler = Box::new(handler);
        self
    }

    /// Filter distributions by TLP label.
    ///
    /// Distributions whose TLP label is not accepted by the filter will be skipped.
    /// Feeds without a TLP label are treated as [`TlpLabel::Unlabeled`]. Directory distributions
    /// (which carry no TLP label) are always included.
    ///
    /// # Examples
    ///
    /// Only walk TLP:CLEAR feeds:
    /// ```ignore
    /// walker.with_tlp_filter(HashSet::from([TlpLabel::Clear]))
    /// ```
    ///
    /// Exclude TLP:GREEN and above (more restrictive):
    /// ```ignore
    /// walker.with_tlp_filter(TlpLabel::Green..)
    /// ```
    pub fn with_tlp_filter(mut self, filter: impl TlpFilter + 'static) -> Self {
        self.tlp_filter = Some(Box::new(filter));
        self
    }

    fn collect_distributions(&self, distributions: Vec<Distribution>) -> Vec<DistributionContext> {
        distributions
            .into_iter()
            .flat_map(|distribution| {
                distribution
                    .rolie
                    .into_iter()
                    .flat_map(|rolie| rolie.feeds)
                    .map(|feed| DistributionContext::Feed {
                        url: feed.url,
                        tlp_label: feed.tlp_label,
                    })
                    .chain(
                        distribution
                            .directory_url
                            .map(DistributionContext::Directory),
                    )
            })
            .filter(|distribution| {
                if let Some(filter) = &self.distribution_filter {
                    filter(distribution)
                } else {
                    true
                }
            })
            .filter(
                |distribution| match (self.tlp_filter.as_ref(), distribution) {
                    (Some(filter), DistributionContext::Feed { tlp_label, .. }) => {
                        filter.include(tlp_label)
                    }
                    _ => true,
                },
            )
            .collect()
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

        let distributions = self.collect_distributions(metadata.distributions);
        log::info!("processing {} distribution URLs", distributions.len());

        for distribution in distributions {
            log::info!("Walking directory URL: {distribution:?}");
            let index = match self.source.load_index(distribution.clone()).await {
                Ok(index) => index,
                Err(e) => {
                    self.distribution_error_handler
                        .handle(&distribution, e)
                        .map_err(Error::Source)?;
                    continue;
                }
            };

            let mut progress = self.progress.start(index.len());

            for advisory in index {
                log::debug!("  Discovered advisory: {advisory:?}");
                progress
                    .set_message(
                        advisory
                            .url
                            .path()
                            .rsplit_once('/')
                            .map(|(_, s)| s)
                            .unwrap_or(advisory.url.as_str())
                            .to_string(),
                    )
                    .await;
                visitor
                    .visit_advisory(&context, advisory)
                    .await
                    .map_err(Error::Visitor)?;
                progress.tick().await;
            }

            progress.finish().await;
        }

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
        let metadata = self.source.load_metadata().await.map_err(Error::Source)?;
        let context = visitor
            .visit_context(&DiscoveredContext {
                metadata: &metadata,
            })
            .await
            .map_err(Error::Visitor)?;

        let context = Arc::new(context);
        let visitor = Arc::new(visitor);

        let distributions = self.collect_distributions(metadata.distributions);
        log::info!("processing {} distribution URLs", distributions.len());

        let advisories: Vec<_> = collect_advisories::<V, S>(
            &self.source,
            distributions,
            &*self.distribution_error_handler,
        )
        .try_collect()
        .await?;

        let size = advisories.len();
        log::info!("Discovered {size} advisories");

        let progress = Arc::new(Mutex::new(self.progress.start(size)));

        stream::iter(advisories)
            .map(Ok)
            .try_for_each_concurrent(limit, async |advisory| {
                log::debug!("Discovered advisory: {}", advisory.url);

                let result = visitor
                    .visit_advisory(&context, advisory.clone())
                    .map_err(Error::Visitor)
                    .await;

                progress.lock().await.tick().await;

                result
            })
            .await?;

        if let Ok(progress) = Arc::try_unwrap(progress) {
            let progress = progress.into_inner();
            progress.finish().await;
        }

        Ok(())
    }
}

#[allow(clippy::needless_lifetimes)] // false positive
fn collect_sources<'s, V: DiscoveredVisitor, S: Source>(
    source: &'s S,
    discover_contexts: Vec<DistributionContext>,
    error_handler: &'s dyn DistributionErrorHandler<S::Error>,
) -> impl TryStream<Ok = impl Stream<Item = DiscoveredAdvisory>, Error = Error<V::Error, S::Error>> + 's
{
    stream::iter(discover_contexts).then(async |discover_context| {
        log::debug!("Walking: {}", discover_context.url());
        match source.load_index(discover_context.clone()).await {
            Ok(index) => Ok(stream::iter(index)),
            Err(e) => {
                error_handler
                    .handle(&discover_context, e)
                    .map_err(Error::Source)?;
                Ok(stream::iter(vec![]))
            }
        }
    })
}

fn collect_advisories<'s, V: DiscoveredVisitor + 's, S: Source>(
    source: &'s S,
    discover_contexts: Vec<DistributionContext>,
    error_handler: &'s dyn DistributionErrorHandler<S::Error>,
) -> impl TryStream<Ok = DiscoveredAdvisory, Error = Error<V::Error, S::Error>> + 's {
    collect_sources::<V, S>(source, discover_contexts, error_handler)
        .map_ok(|s| s.map(Ok))
        .try_flatten()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        model::metadata::{Feed, Rolie},
        source::FileSource,
    };
    use url::Url;

    fn distributions() -> Vec<Distribution> {
        let feed = |label: TlpLabel| Feed {
            summary: None,
            tlp_label: label,
            url: Url::parse(&format!("https://example.com/{label}.json")).unwrap(),
        };

        vec![Distribution {
            directory_url: Some(Url::parse("https://example.com/directory/").unwrap()),
            rolie: Some(Rolie {
                categories: vec![],
                feeds: vec![
                    feed(TlpLabel::Unlabeled),
                    feed(TlpLabel::Clear),
                    feed(TlpLabel::Green),
                ],
                services: vec![],
            }),
        }]
    }

    fn collect(walker: Walker<FileSource, ()>) -> Vec<String> {
        walker
            .collect_distributions(distributions())
            .iter()
            .map(|distribution| distribution.url().path().to_string())
            .collect()
    }

    #[test]
    fn tlp_filter_none() {
        let walker = Walker::new(FileSource::new(".", None).unwrap());
        assert_eq!(
            collect(walker),
            [
                "/unlabeled.json",
                "/clear.json",
                "/green.json",
                "/directory/"
            ]
        );
    }

    #[test]
    fn tlp_filter_excludes_unlabeled() {
        let walker = Walker::new(FileSource::new(".", None).unwrap())
            .with_tlp_filter(HashSet::from([TlpLabel::Clear]));
        assert_eq!(collect(walker), ["/clear.json", "/directory/"]);
    }

    #[test]
    fn tlp_filter_includes_unlabeled() {
        let walker = Walker::new(FileSource::new(".", None).unwrap())
            .with_tlp_filter(HashSet::from([TlpLabel::Unlabeled]));
        assert_eq!(collect(walker), ["/unlabeled.json", "/directory/"]);
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
