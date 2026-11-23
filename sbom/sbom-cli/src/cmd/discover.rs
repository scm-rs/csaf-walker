use crate::cmd::DiscoverArguments;
use sbom_walker::{discover::DiscoveredSbom, source::new_source, walker::Walker};
use std::convert::Infallible;
use walker_common::{
    cli::{CommandDefaults, client::ClientArguments},
    progress::Progress,
    utils::time::Human,
};

/// Discover SBOMs, just lists the URLs.
#[derive(clap::Args, Debug)]
pub struct Discover {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,
}

impl CommandDefaults for Discover {
    fn progress(&self) -> bool {
        false
    }
}

impl Discover {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        Walker::new(new_source(self.discover, self.client).await?)
            .with_progress(progress.clone())
            .walk(async |discovered: DiscoveredSbom| {
                progress.println(&format!(
                    "{} ({})",
                    discovered.url,
                    Human(discovered.modified),
                ));

                Ok::<_, Infallible>(())
            })
            .await?;

        Ok(())
    }
}
