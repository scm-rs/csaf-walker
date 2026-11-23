use super::{Credentials, Expires, TokenProvider};
use crate::sender::Error;
use core::fmt::{self, Debug, Formatter};
use std::{ops::Deref, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "clap")]
use {crate::utils::time::SpanExt, anyhow::Context, jiff::Span, url::Url};

#[cfg(feature = "clap")]
#[derive(Clone, Debug, clap::Args)]
#[cfg_attr(feature = "clap", command(next_help_heading = "OIDC"))]
pub struct OpenIdTokenProviderConfigArguments {
    /// The client ID for using Open ID connect
    #[arg(
        id = "oidc_client_id",
        long = "oidc-client-id",
        env = "OIDC_CLIENT_ID",
        requires("OpenIdTokenProviderConfigArguments")
    )]
    pub client_id: Option<String>,
    /// The client secret for using Open ID connect
    #[arg(
        id = "oidc_client_secret",
        long = "oidc-client-secret",
        env = "OIDC_CLIENT_SECRET",
        requires("OpenIdTokenProviderConfigArguments")
    )]
    pub client_secret: Option<String>,
    /// The issuer URL for using Open ID connect
    #[arg(
        id = "oidc_issuer_url",
        long = "oidc-issuer-url",
        env = "OIDC_ISSUER_URL",
        requires("OpenIdTokenProviderConfigArguments")
    )]
    pub issuer_url: Option<String>,
    /// The time a token must be valid before refreshing it
    #[arg(
        id = "oidc_refresh_before",
        long = "oidc-refresh-before",
        env = "OIDC_REFRESH_BEFORE",
        default_value = "30s"
    )]
    pub refresh_before: Span,
    /// Allows using TLS in an insecure mode when connecting the OIDC issuer (DANGER!)
    #[arg(
        id = "oidc_tls_insecure",
        long = "oidc-tls-insecure",
        default_value = "false"
    )]
    pub tls_insecure: bool,
    /// Allows adding additional trust anchors
    #[arg(
        id = "oidc_tls_ca_certificates",
        long = "oidc-tls-ca-certificate",
        action = clap::ArgAction::Append,
    )]
    pub tls_ca_certificates: Vec<std::path::PathBuf>,
}

#[cfg(feature = "clap")]
impl OpenIdTokenProviderConfigArguments {
    pub async fn into_provider(self) -> anyhow::Result<Arc<dyn TokenProvider>> {
        OpenIdTokenProviderConfig::new_provider(OpenIdTokenProviderConfig::from_args(self)).await
    }
}

#[cfg(feature = "clap")]
#[derive(Clone, Debug, clap::Args)]
pub struct OpenIdTokenProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub refresh_before: Span,
    pub tls_insecure: bool,
    pub tls_ca_certificates: Vec<std::path::PathBuf>,
}

#[cfg(feature = "clap")]
impl OpenIdTokenProviderConfig {
    pub async fn new_provider(config: Option<Self>) -> anyhow::Result<Arc<dyn TokenProvider>> {
        Ok(match config {
            Some(config) => Arc::new(OpenIdTokenProvider::with_config(config).await?),
            None => Arc::new(()),
        })
    }

    pub fn from_args(arguments: OpenIdTokenProviderConfigArguments) -> Option<Self> {
        match (
            arguments.client_id,
            arguments.client_secret,
            arguments.issuer_url,
        ) {
            (Some(client_id), Some(client_secret), Some(issuer_url)) => {
                Some(OpenIdTokenProviderConfig {
                    client_id,
                    client_secret,
                    issuer_url,
                    refresh_before: arguments.refresh_before,
                    tls_insecure: arguments.tls_insecure,
                    tls_ca_certificates: arguments.tls_ca_certificates,
                })
            }
            _ => None,
        }
    }
}

#[cfg(feature = "clap")]
impl From<OpenIdTokenProviderConfigArguments> for Option<OpenIdTokenProviderConfig> {
    fn from(value: OpenIdTokenProviderConfigArguments) -> Self {
        OpenIdTokenProviderConfig::from_args(value)
    }
}

/// A provider which provides access tokens for clients.
#[derive(Clone)]
pub struct OpenIdTokenProvider {
    client: Arc<openid::Client>,
    current_token: Arc<RwLock<Option<openid::TemporalBearerGuard>>>,
    refresh_before: time::Duration,
}

impl Debug for OpenIdTokenProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenProvider")
            .field(
                "client",
                &format!("{} / {:?}", self.client.client_id, self.client.http_client),
            )
            .field("current_token", &"...")
            .finish()
    }
}

impl OpenIdTokenProvider {
    /// Create a new provider using the provided client.
    pub fn new(client: openid::Client, refresh_before: time::Duration) -> Self {
        Self {
            client: Arc::new(client),
            current_token: Arc::new(RwLock::new(None)),
            refresh_before,
        }
    }

    #[cfg(feature = "clap")]
    pub async fn with_config(config: OpenIdTokenProviderConfig) -> anyhow::Result<Self> {
        let issuer = Url::parse(&config.issuer_url).context("Parse issuer URL")?;

        let mut client = reqwest::ClientBuilder::new();

        if config.tls_insecure {
            log::warn!("Using insecure TLS when communicating with the OIDC issuer");
            client = client
                .danger_accept_invalid_hostnames(true)
                .danger_accept_invalid_certs(true);
        }

        for cert in config.tls_ca_certificates {
            client = crate::utils::pem::add_cert(client, &cert)
                .with_context(|| format!("adding trust anchor: {}", cert.display()))?;
        }

        let client = openid::Client::discover_with_client(
            client.build()?,
            config.client_id,
            config.client_secret,
            None,
            issuer,
        )
        .await
        .context("Discover OIDC client")?;

        Ok(Self::new(
            client,
            time::Duration::try_from(config.refresh_before.to_std_duration()?)?,
        ))
    }

    /// return a fresh token, this may be an existing (non-expired) token
    /// a newly refreshed token.
    pub async fn provide_token(&self) -> Result<openid::Bearer, openid::error::Error> {
        match self.current_token.read().await.deref() {
            Some(token) if !token.expires_before(self.refresh_before) => {
                log::debug!("Token still valid");
                return Ok(token.as_ref().clone());
            }
            _ => {}
        }

        // fetch fresh token after releasing the read lock

        self.fetch_fresh_token().await
    }

    async fn fetch_fresh_token(&self) -> Result<openid::Bearer, openid::error::Error> {
        log::debug!("Fetching fresh token...");

        let mut lock = self.current_token.write().await;

        match lock.deref() {
            // check if someone else refreshed the token in the meantime
            Some(token) if !token.expires_before(self.refresh_before) => {
                log::debug!("Token already got refreshed");
                return Ok(token.as_ref().clone());
            }
            _ => {}
        }

        // we hold the write-lock now, and can perform the refresh operation

        let next_token = match lock.take() {
            // if we don't have any token, fetch an initial one
            None => {
                log::debug!("Fetching initial token... ");
                self.initial_token().await?
            }
            // if we have an expired one, refresh it
            Some(current_token) => {
                log::debug!("Refreshing token ... ");
                match current_token.as_ref().refresh_token.is_some() {
                    true => self.client.refresh_token(current_token, None).await?.into(),
                    false => self.initial_token().await?,
                }
            }
        };

        log::debug!("Next token: {:?}", next_token.as_ref());

        let result = next_token.as_ref().clone();
        lock.replace(next_token);

        // done

        Ok(result)
    }

    async fn initial_token(&self) -> Result<openid::TemporalBearerGuard, openid::error::Error> {
        Ok(self
            .client
            .request_token_using_client_credentials(None)
            .await?
            .into())
    }
}

#[async_trait::async_trait]
impl TokenProvider for OpenIdTokenProvider {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(self
            .provide_token()
            .await
            .map(|token| Some(Credentials::Bearer(token.access_token)))?)
    }
}
