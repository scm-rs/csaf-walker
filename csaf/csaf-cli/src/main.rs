#![forbid(unsafe_code)]

mod cmd;
mod common;

use clap::Parser;
use cmd::{
    discover::Discover, download::Download, fetch::Fetch, metadata::Metadata, parse::Parse,
    report::Report, scan::Scan, scoop::Scoop, send::Send, sync::Sync, validate::Validate,
};
use std::{ops::Deref, process::ExitCode};
use walker_common::{
    cli::CommandDefaults, cli::log::Logging, progress::Progress, utils::measure::MeasureTime,
};

#[derive(Debug, Parser)]
#[command(version, about = "CSAF Tool", author, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    logging: Logging,
}

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
enum Command {
    Parse(Parse),
    Download(Download),
    Fetch(Fetch),
    Scan(Scan),
    Discover(Discover),
    Sync(Sync),
    Report(Report),
    Send(Send),
    Metadata(Metadata),
    Scoop(Scoop),
    Validate(Validate),
}

impl Deref for Command {
    type Target = dyn CommandDefaults;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Parse(cmd) => cmd,
            Self::Download(cmd) => cmd,
            Self::Fetch(cmd) => cmd,
            Self::Scan(cmd) => cmd,
            Self::Discover(cmd) => cmd,
            Self::Sync(cmd) => cmd,
            Self::Report(cmd) => cmd,
            Self::Send(cmd) => cmd,
            Self::Metadata(cmd) => cmd,
            Self::Scoop(cmd) => cmd,
            Self::Validate(cmd) => cmd,
        }
    }
}

impl Command {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        match self {
            Self::Parse(cmd) => cmd.run(progress).await,
            Self::Download(cmd) => cmd.run(progress).await,
            Self::Fetch(cmd) => cmd.run(progress).await,
            Self::Scan(cmd) => cmd.run(progress).await,
            Self::Discover(cmd) => cmd.run(progress).await,
            Self::Sync(cmd) => cmd.run(progress).await,
            Self::Report(cmd) => cmd.run(progress).await,
            Self::Send(cmd) => cmd.run(progress).await,
            Self::Metadata(cmd) => cmd.run().await,
            Self::Scoop(cmd) => cmd.run(progress).await,
            Self::Validate(cmd) => cmd.run(progress).await,
        }
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let progress = self
            .logging
            .init(&["csaf", "csaf_walker"], self.command.progress());

        // run

        log::debug!("Setup complete, start processing");

        let time = MeasureTime::new();
        self.command.run(progress).await?;
        drop(time);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = Cli::parse().run().await {
        log::error!("Failed to execute: {err}");
        for (n, cause) in err.chain().enumerate().skip(1) {
            log::info!("  {n}: {cause}");
        }
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
