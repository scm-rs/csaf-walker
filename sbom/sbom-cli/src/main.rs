#![forbid(unsafe_code)]
extern crate core;

mod cmd;
mod common;
mod inspect;

use crate::cmd::{
    discover::Discover, download::Download, inspect::Inspect, report::Report, scan::Scan,
    scoop::Scoop, send::Send, sync::Sync,
};
use clap::Parser;
use std::{ops::Deref, process::ExitCode};
use walker_common::{
    cli::{CommandDefaults, log::Logging},
    progress::Progress,
    utils::measure::MeasureTime,
};

#[derive(Debug, Parser)]
#[command(version, about = "SBOM Tool", author, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    logging: Logging,
}

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
enum Command {
    Discover(Discover),
    Download(Download),
    Sync(Sync),
    Scan(Scan),
    Report(Report),
    Send(Send),
    Scoop(Scoop),
    Inspect(Inspect),
}

impl Deref for Command {
    type Target = dyn CommandDefaults;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Download(cmd) => cmd,
            Self::Scan(cmd) => cmd,
            Self::Discover(cmd) => cmd,
            Self::Sync(cmd) => cmd,
            Self::Report(cmd) => cmd,
            Self::Send(cmd) => cmd,
            Self::Scoop(cmd) => cmd,
            Self::Inspect(cmd) => cmd,
        }
    }
}

impl Command {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        match self {
            Self::Discover(cmd) => cmd.run(progress).await,
            Self::Download(cmd) => cmd.run(progress).await,
            Self::Sync(cmd) => cmd.run(progress).await,
            Self::Scan(cmd) => cmd.run(progress).await,
            Self::Report(cmd) => cmd.run(progress).await,
            Self::Send(cmd) => cmd.run(progress).await,
            Self::Scoop(cmd) => cmd.run(progress).await,
            Self::Inspect(cmd) => cmd.run(progress).await,
        }
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let progress = self
            .logging
            .init(&["sbom", "sbom_walker"], self.command.progress());

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

#[cfg(test)]
mod cli_tests {
    #[test]
    fn command_arguments_are_consistent() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}
