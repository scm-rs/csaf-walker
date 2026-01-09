use crate::{
    cmd::{DiscoverArguments, SkipArguments},
    common::walk_visitor,
};
use sbom_walker::{
    discover::DiscoverConfig, retrieve::RetrievingVisitor, validation::ValidationVisitor,
    visitors::skip::SkipFailedVisitor,
};
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    progress::Progress,
    since::Since,
    validate::ValidationOptions,
};
use walker_extras::visitors::{SendArguments, SendVisitor};

/// Walk a source and send validated/retrieved documents to a sink.
#[derive(clap::Args, Debug)]
pub struct Send {
    /// Skip (with a warning) documents which failed processing
    #[arg(long)]
    skip_failures: bool,

    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    skip: SkipArguments,

    #[command(flatten)]
    send: SendArguments,
}

impl CommandDefaults for Send {}

impl Send {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();
        let send: SendVisitor = self.send.into_visitor().await?;

        let since = Since::new(
            self.skip.since,
            self.skip.since_file,
            self.skip
                .since_file_offset
                .map(|d| d.into())
                .unwrap_or_default(),
        )?;

        log::debug!("Start walking");

        walk_visitor(
            progress,
            self.client,
            DiscoverConfig::from(self.discover).with_since(since.since),
            self.runner,
            async move |source| {
                let visitor = {
                    RetrievingVisitor::new(source.clone(), {
                        ValidationVisitor::new(SkipFailedVisitor {
                            skip_failures: self.skip_failures,
                            visitor: send,
                        })
                        .with_options(options)
                    })
                };

                Ok(visitor)
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
