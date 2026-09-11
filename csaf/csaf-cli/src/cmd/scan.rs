use crate::{
    cmd::{DiscoverArguments, FilterArguments},
    common::walk_standard,
};
use csaf_walker::verification::Csaf;
use csaf_walker::{
    source::DispatchSource,
    validation::{ValidatedAdvisory, ValidationError},
};
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    progress::Progress,
};

/// Scan advisories
#[derive(clap::Args, Debug)]
pub struct Scan {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,
}

impl CommandDefaults for Scan {}

impl Scan {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        walk_standard(
            progress.clone(),
            self.client,
            self.runner,
            self.discover,
            self.filter,
            self.validation,
            async |advisory: Result<ValidatedAdvisory, ValidationError<DispatchSource>>| {
                match advisory {
                    Ok(adv) => {
                        progress.println(&format!("Advisory: {}", adv.url));
                        log::debug!("  Metadata: {:?}", adv.sha256);
                        log::debug!("    SHA256: {:?}", adv.sha256);
                        log::debug!("    SHA512: {:?}", adv.sha512);
                        match Csaf::parse(&*adv.data) {
                            Ok(csaf) => {
                                progress.println(&format!(
                                    "  {} ({}): {}",
                                    csaf.document().tracking().id(),
                                    csaf.document().tracking().initial_release_date(),
                                    csaf.document().title()
                                ));
                            }
                            Err(err) => {
                                eprintln!("  Format error: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Advisory(ERR): {err}");
                    }
                }

                Ok::<_, anyhow::Error>(())
            },
        )
        .await?;

        Ok(())
    }
}
