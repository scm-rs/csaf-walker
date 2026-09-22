use crate::cmd::DiscoverArguments;
use csaf_walker::{
    discover::{DiscoverConfig, DiscoveredVisitor},
    retrieve::RetrievingVisitor,
    source::{DispatchSource, new_source},
    validation::{ValidatedVisitor, ValidationVisitor},
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::{DistributionConfig, Walker},
};
use std::future::Future;
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    validate::ValidationOptions,
};

pub async fn walk_standard<V, P>(
    progress: P,
    client: ClientArguments,
    runner: RunnerArguments,
    discover: impl Into<DiscoverConfig>,
    filter: impl Into<FilterConfig>,
    distribution: impl Into<DistributionConfig>,
    validation: ValidationArguments,
    visitor: V,
) -> anyhow::Result<()>
where
    V: ValidatedVisitor<DispatchSource>,
    V::Error: Send + Sync + 'static,
    P: Progress,
{
    let options: ValidationOptions = validation.into();

    walk_visitor(
        progress,
        client,
        discover,
        filter,
        distribution,
        runner,
        async move |source| {
            Ok(RetrievingVisitor::new(
                source.clone(),
                ValidationVisitor::new(visitor).with_options(options),
            ))
        },
    )
    .await
}

impl From<DiscoverArguments> for DiscoverConfig {
    fn from(value: DiscoverArguments) -> Self {
        Self {
            since: None,
            source: value.source,
        }
    }
}

/// Create a [`FilteringVisitor`] from a [`FilterConfig`].
pub fn filter<V>(filter: impl Into<FilterConfig>, visitor: V) -> FilteringVisitor<V>
where
    V: DiscoveredVisitor,
{
    FilteringVisitor {
        visitor,
        config: filter.into(),
    }
}

pub async fn walk_visitor<F, Fut, V, P>(
    progress: P,
    client: ClientArguments,
    discover: impl Into<DiscoverConfig>,
    filter: impl Into<FilterConfig>,
    distribution: impl Into<DistributionConfig>,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
    P: Progress,
{
    let source = new_source(discover, client).await?;

    walk_source(progress, source, filter, distribution, runner, f).await
}

pub async fn walk_source<F, Fut, V, P>(
    progress: P,
    source: DispatchSource,
    filter_config: impl Into<FilterConfig>,
    distribution: impl Into<DistributionConfig>,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
    P: Progress,
{
    let visitor = f(source.clone()).await?;
    let distribution = distribution.into();
    let mut walker = Walker::new(source).with_progress(progress);

    if let Some(filter) = distribution.tlp_filter {
        walker = walker.with_tlp_filter(filter);
    }

    match runner.workers {
        1 => {
            walker.walk(filter(filter_config, visitor)).await?;
        }
        n => {
            walker
                .walk_parallel(n, filter(filter_config, visitor))
                .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use csaf_walker::source::SourceDescriptor;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_file_relative() {
        let source = SourceDescriptor::from_str("file:../../foo/bar");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "../../foo/bar")
        );
    }

    #[tokio::test]
    async fn test_file_absolute() {
        let source = SourceDescriptor::from_str("file:/foo/bar");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "/foo/bar")
        );
    }

    #[tokio::test]
    async fn test_file_absolute_double() {
        let source = SourceDescriptor::from_str("file:///foo/bar");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "/foo/bar")
        );
    }

    #[tokio::test]
    async fn test_file_absolute_windows() {
        let source = SourceDescriptor::from_str("file:///c:/DATA/example");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "/c:/DATA/example")
        );
    }

    #[tokio::test]
    async fn test_base() {
        let source = SourceDescriptor::from_str("base.domain");
        println!("Result: {source:?}");
        assert!(matches!(source, Ok(SourceDescriptor::Lookup(base)) if base == "base.domain"));
    }

    #[tokio::test]
    async fn test_https() {
        let source = SourceDescriptor::from_str("https://base.domain");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::Url(url)) if url.as_str() == "https://base.domain/")
        );
    }

    #[tokio::test]
    async fn test_gopher() {
        let source = SourceDescriptor::from_str("gopher://base.domain");
        println!("Result: {source:?}");
        assert!(source.is_err());
    }
}
