use crate::{
    cmd::{DiscoverArguments, FilterArguments, SkipArguments, StoreArguments},
    common::walk_visitor,
};
use csaf_walker::{
    discover::DiscoverConfig,
    retrieve::RetrievingVisitor,
    visitors::{skip::SkipExistingVisitor, store::StoreVisitor},
};
use walker_common::{
    cli::{CommandDefaults, client::ClientArguments, runner::RunnerArguments},
    progress::Progress,
    since::Since,
};

/// Like sync, but doesn't validate.
#[derive(clap::Args, Debug)]
pub struct Download {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    skip: SkipArguments,

    #[command(flatten)]
    store: StoreArguments,
}

impl CommandDefaults for Download {}

impl Download {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let store: StoreVisitor = self.store.try_into()?;
        let base = store.base.clone();

        let since = Since::new(
            self.skip.since,
            self.skip.since_file,
            self.skip
                .since_file_offset
                .map(|d| d.into())
                .unwrap_or_default(),
        )?;

        walk_visitor(
            progress,
            self.client,
            DiscoverConfig::from(self.discover).with_since(since.since),
            self.filter,
            self.runner,
            async |source| {
                let visitor = RetrievingVisitor::new(source.clone(), store);

                Ok(SkipExistingVisitor {
                    visitor,
                    output: base,
                    since: since.since,
                })
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
