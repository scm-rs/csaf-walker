use crate::fetcher::{Fetcher, FetcherOptions};

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Client")]
pub struct ClientArguments {
    /// Per-request HTTP timeout, in humantime duration format.
    #[arg(short, long, default_value = "5s")]
    pub timeout: humantime::Duration,

    /// Per-request retries count
    #[arg(short, long, default_value = "5")]
    pub retries: usize,

    /// Per-request minimum delay after rate limit (429).
    #[arg(long, default_value = "10s")]
    pub default_retry_after: humantime::Duration,
}

impl From<ClientArguments> for FetcherOptions {
    fn from(value: ClientArguments) -> Self {
        FetcherOptions {
            timeout: value.timeout.into(),
            retries: value.retries,
            default_retry_after: value.default_retry_after.into(),
        }
    }
}

impl ClientArguments {
    /// Create a new [`Fetcher`] from arguments.
    pub async fn new_fetcher(self) -> Result<Fetcher, anyhow::Error> {
        Fetcher::new(self.into()).await
    }
}
