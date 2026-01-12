use anyhow::Context;
use flexible_time::timestamp::StartTimestamp;
use reqwest::Url;
use sbom_walker::visitors::store::StoreVisitor;
use std::path::PathBuf;

pub mod discover;
pub mod download;
pub mod inspect;
pub mod report;
pub mod scan;
pub mod scoop;
pub mod send;
pub mod sync;

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Discovery")]
pub struct DiscoverArguments {
    /// Source to scan from
    pub source: String,
    #[arg(short = 'k', long = "key")]
    /// URLs to keys which should be used for validation. The fragment part of a key can be used as the fingerprint.
    pub keys: Vec<Url>,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Storage")]
pub struct StoreArguments {
    /// Disable applying the modification timestamp to the downloaded file.
    #[arg(long)]
    pub no_timestamps: bool,

    /// Output path, defaults to the local directory.
    #[arg(short, long)]
    pub data: Option<PathBuf>,
}

impl TryFrom<StoreArguments> for StoreVisitor {
    type Error = anyhow::Error;

    fn try_from(value: StoreArguments) -> Result<Self, Self::Error> {
        let base = match value.data {
            Some(base) => base,
            None => std::env::current_dir().context("Get the current working directory")?,
        };

        Ok(Self::new(base).no_timestamps(value.no_timestamps))
    }
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Skipping")]
pub struct SkipArguments {
    /// Provide a timestamp since when files are considered changed.
    #[arg(short, long)]
    pub since: Option<StartTimestamp>,

    /// A file to read/store the last sync timestamp to at the end of a successful run.
    #[arg(short = 'S', long)]
    pub since_file: Option<PathBuf>,

    /// A delta to add to the value loaded from the since-state file.
    #[arg(long)]
    pub since_file_offset: Option<humantime::Duration>,
}
