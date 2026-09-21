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

    /// The user agent to send with requests.
    #[arg(long, default_value = crate::USER_AGENT)]
    pub user_agent: String,
}

impl From<ClientArguments> for FetcherOptions {
    fn from(value: ClientArguments) -> Self {
        FetcherOptions::new()
            .timeout(value.timeout)
            .retries(value.retries)
            .retry_after(value.default_retry_after.into())
            .user_agent(value.user_agent)
    }
}

impl ClientArguments {
    /// Create a new [`Fetcher`] from arguments.
    pub async fn new_fetcher(self) -> Result<Fetcher, anyhow::Error> {
        Fetcher::new(self.into()).await
    }
}
