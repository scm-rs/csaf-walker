use crate::{
    cmd::{DiscoverArguments, DistributionArguments, FilterArguments},
    common::filter,
};
use csaf_walker::{
    discover::DiscoveredAdvisory,
    source::new_source,
    walker::{DistributionConfig, Walker},
};
use std::convert::Infallible;
use walker_common::{
    cli::{CommandDefaults, client::ClientArguments},
    progress::Progress,
};

/// Discover advisories, just lists the URLs.
#[derive(clap::Args, Debug)]
pub struct Discover {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    distribution: DistributionArguments,
}

impl CommandDefaults for Discover {
    fn progress(&self) -> bool {
        false
    }
}

impl Discover {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        let distribution: DistributionConfig = self.distribution.into();
        let mut walker = Walker::new(new_source(self.discover, self.client).await?)
            .with_progress(progress.clone());

        if let Some(tlp_filter) = distribution.tlp_filter {
            walker = walker.with_tlp_filter(tlp_filter);
        }

        walker
            .walk(filter(
                self.filter,
                async |discovered: DiscoveredAdvisory| {
                    progress.println(&format!("{}", discovered.url));

                    Ok::<_, Infallible>(())
                },
            ))
            .await?;

        Ok(())
    }
}
