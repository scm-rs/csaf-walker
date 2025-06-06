use crate::{cmd::DiscoverArguments, common::walk_standard};
use sbom_walker::{
    Sbom, discover::DiscoveredSbom, retrieve::RetrievedSbom, source::DispatchSource,
    validation::ValidatedSbom,
};
use tokio::task;
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    compression::decompress,
    progress::Progress,
    validate::ValidationError,
};

/// Scan SBOMs
#[derive(clap::Args, Debug)]
pub struct Scan {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,
}

impl CommandDefaults for Scan {}

impl Scan {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        walk_standard(
            progress,
            self.client,
            self.runner,
            self.discover,
            self.validation,
            async |advisory: Result<ValidatedSbom, ValidationError<DispatchSource>>| {
                match advisory {
                    Ok(sbom) => {
                        println!("Advisory: {}", sbom.url);
                        log::debug!("  Metadata: {:?}", sbom.sha256);
                        log::debug!("    SHA256: {:?}", sbom.sha256);
                        log::debug!("    SHA512: {:?}", sbom.sha512);

                        let ValidatedSbom {
                            retrieved:
                                RetrievedSbom {
                                    data,
                                    discovered: DiscoveredSbom { url, .. },
                                    ..
                                },
                        } = sbom;

                        let data =
                            task::spawn_blocking(move || decompress(data, url.path())).await??;

                        match Sbom::try_parse_any(&data) {
                            Ok(sbom) => process_sbom(sbom),
                            Err(err) => {
                                eprintln!("  Format error: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("SBOM(ERR): {err}");
                    }
                }

                Ok::<_, anyhow::Error>(())
            },
        )
        .await?;

        Ok(())
    }
}

fn process_sbom(sbom: Sbom) {
    match sbom {
        Sbom::Spdx(sbom) => {
            println!(
                "  SPDX: {}",
                sbom.document_creation_information.document_name
            );
        }

        Sbom::SerdeCycloneDx(_sbom) => {
            println!("  CycloneDX");
        }
    }
}
