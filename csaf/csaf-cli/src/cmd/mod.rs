use anyhow::Context;
use csaf_walker::visitors::{filter::FilterConfig, store::StoreVisitor};
use flexible_time::timestamp::StartTimestamp;
use std::path::PathBuf;
use walker_common::cli::parser::parse_allow_client_errors;

pub mod discover;
pub mod download;
pub mod fetch;
pub mod metadata;
pub mod parse;
pub mod report;
pub mod scan;
pub mod scoop;
pub mod send;
pub mod sync;

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Discovery")]
pub struct DiscoverArguments {
    /// Source to scan from.
    ///
    /// CSAF trusted provider base domain (e.g. `redhat.com`), the full URL to the provider metadata file, or a local `file:` source.
    pub source: String,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Filters")]
pub struct FilterArguments {
    #[arg(long)]
    /// Distributions to ignore
    pub ignore_distribution: Vec<String>,

    #[arg(long)]
    /// Prefix to ignore
    pub ignore_prefix: Vec<String>,

    #[arg(long)]
    /// Ignore all non-matching prefixes
    pub only_prefix: Vec<String>,
}

impl From<FilterArguments> for FilterConfig {
    fn from(filter: FilterArguments) -> Self {
        FilterConfig::new()
            .ignored_distributions(filter.ignore_distribution)
            .ignored_prefixes(filter.ignore_prefix)
            .only_prefixes(filter.only_prefix)
    }
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Storage")]
pub struct StoreArguments {
    /// Disable the use of extended attributes, e.g. for etag information.
    #[arg(long)]
    pub no_xattrs: bool,

    /// Disable applying the modification timestamp to the downloaded file.
    #[arg(long)]
    pub no_timestamps: bool,

    /// Output path, defaults to the local directory.
    #[arg(short, long)]
    pub data: Option<PathBuf>,

    /// Shorthand for `--allow-client-errors 404`.
    #[arg(long)]
    pub allow_missing: bool,

    /// Continue processing even if some documents could not be retrieved due to 4xx (client) errors.
    #[arg(long)]
    pub allow_client_errors: Vec<String>,
}

impl TryFrom<StoreArguments> for StoreVisitor {
    type Error = anyhow::Error;

    fn try_from(value: StoreArguments) -> Result<Self, Self::Error> {
        let base = match value.data {
            Some(base) => base,
            None => std::env::current_dir().context("Get current working directory")?,
        };

        let allow_client_errors =
            parse_allow_client_errors(value.allow_missing, value.allow_client_errors)?;

        let result = Self::new(base)
            .no_timestamps(value.no_timestamps)
            .allow_client_errors(allow_client_errors);

        let result = result.no_xattrs(value.no_xattrs);

        Ok(result)
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

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Checks")]
pub struct VerificationArguments {}
