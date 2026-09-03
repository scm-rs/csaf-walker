use csaf_walker::verification::Csaf;
use std::path::PathBuf;
use walker_common::{cli::CommandDefaults, progress::Progress};

/// Parse advisories
#[derive(clap::Args, Debug)]
pub struct Parse {
    file: PathBuf,
}

impl CommandDefaults for Parse {}

impl Parse {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        progress.start(1);

        match Csaf::parse(&self.file) {
            Ok(csaf) => {
                println!(
                    "  {} ({}): {}",
                    csaf.document().tracking().id(),
                    csaf.document().tracking().initial_release_date(),
                    csaf.document().title()
                );
            }
            Err(err) => {
                eprintln!("  Format error: {err}");
            }
        }

        Ok(())
    }
}
