use crate::visitors::SendVisitor;
use reqwest::Url;
use std::path::PathBuf;
use walker_common::sender::{
    HttpSender, HttpSenderOptions, provider::OpenIdTokenProviderConfigArguments,
};

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Sending")]
pub struct SendArguments {
    /// Target to send to
    pub target: Url,

    /// Sender connect timeout
    #[arg(
        id = "sender-connect-timeout",
        long,
        env = "SENDER_CONNECT_TIMEOUT",
        default_value = "15s"
    )]
    pub connect_timeout: humantime::Duration,

    /// Sender request timeout
    #[arg(
        id = "sender-timeout",
        long,
        env = "SENDER_TIMEOUT",
        default_value = "5m"
    )]
    pub timeout: humantime::Duration,

    /// Additional root certificates
    #[arg(id = "sender-tls-ca-certificate", long)]
    pub additional_root_certificates: Vec<PathBuf>,

    /// Allow using TLS in an insecure mode when contacting the target (DANGER!)
    #[arg(id = "sender-tls-insecure", long)]
    pub tls_insecure: bool,

    /// Number of retries in case of temporary failures
    #[arg(
        id = "sender-retries",
        long,
        env = "SENDER_RETRIES",
        default_value = "0"
    )]
    pub retries: usize,

    /// Minimum delay between retries
    #[arg(
        id = "sender-min-delay",
        long,
        env = "SENDER_MIN_DELAY",
        default_value = "1s"
    )]
    pub min_delay: humantime::Duration,

    /// Maximum delay between retries
    #[arg(
        id = "sender-max-delay",
        long,
        env = "SENDER_MAX_DELAY",
        default_value = "60s"
    )]
    pub max_delay: humantime::Duration,

    /// Custom query parameters
    #[arg(
        id = "sender-query-parameter",
        long,
        env = "SENDER_QUERY_PARAMETER",
        value_delimiter = ','
    )]
    pub query: Vec<String>,

    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,
}

impl SendArguments {
    pub async fn into_visitor(self) -> Result<SendVisitor, anyhow::Error> {
        let SendArguments {
            target,
            connect_timeout,
            timeout,
            additional_root_certificates,
            tls_insecure,
            retries,
            min_delay,
            max_delay,
            oidc,
            query,
        } = self;

        let provider = oidc.into_provider().await?;
        let sender = HttpSender::new(
            provider,
            HttpSenderOptions::default()
                .connect_timeout(Some(connect_timeout.into()))
                .timeout(Some(timeout.into()))
                .tls_insecure(tls_insecure)
                .additional_root_certificates(additional_root_certificates)
                .query_parameters(query.into_iter().map(|entry| match entry.split_once('=') {
                    Some((key, value)) => (key.to_string(), value.to_string()),
                    None => (entry, "".to_string()),
                })),
        )
        .await?;

        Ok(SendVisitor::new(target, sender)
            .retries(retries)
            .min_delay(min_delay)
            .max_delay(max_delay))
    }
}
