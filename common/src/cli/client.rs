use crate::fetcher::{FetchAuthentication, Fetcher, FetcherOptions};

#[derive(clap::Parser)]
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

    /// Bearer token sent with every fetch request.
    #[arg(long, conflicts_with_all = ["fetch_auth_header", "fetch_username", "fetch_password"])]
    pub fetch_bearer_token: Option<String>,

    /// Custom authentication header sent with every fetch request (NAME: VALUE).
    #[arg(long, value_name = "NAME: VALUE", conflicts_with_all = ["fetch_username", "fetch_password"])]
    pub fetch_auth_header: Option<String>,

    /// Basic authentication username sent with every fetch request.
    #[arg(long, requires = "fetch_password")]
    pub fetch_username: Option<String>,

    /// Basic authentication password (may be empty).
    #[arg(long, requires = "fetch_username")]
    pub fetch_password: Option<String>,
}

impl std::fmt::Debug for ClientArguments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientArguments")
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .field("default_retry_after", &self.default_retry_after)
            .field("user_agent", &self.user_agent)
            .field(
                "fetch_bearer_token",
                &self.fetch_bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "fetch_auth_header",
                &self.fetch_auth_header.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "fetch_username",
                &self.fetch_username.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "fetch_password",
                &self.fetch_password.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl From<ClientArguments> for FetcherOptions {
    fn from(value: ClientArguments) -> Self {
        let mut options = FetcherOptions::new()
            .timeout(value.timeout)
            .retries(value.retries)
            .retry_after(value.default_retry_after.into())
            .user_agent(value.user_agent);
        let authentication = if let Some(token) = value.fetch_bearer_token {
            Some(FetchAuthentication::Bearer(token))
        } else if let Some(header) = value.fetch_auth_header {
            // An absent separator produces an invalid name, rejected during Fetcher::new
            // without echoing the potentially secret input in a clap parsing error.
            let (name, value) = header.split_once(':').unwrap_or(("", &header));
            Some(FetchAuthentication::Header {
                name: name.trim().into(),
                value: value.trim().into(),
            })
        } else {
            value
                .fetch_username
                .map(|username| FetchAuthentication::Basic {
                    username,
                    password: value.fetch_password.unwrap_or_default(),
                })
        };
        if let Some(authentication) = authentication {
            options = options.authentication(authentication);
        }
        options
    }
}

impl ClientArguments {
    /// Create a new [`Fetcher`] from arguments.
    pub async fn new_fetcher(self) -> Result<Fetcher, anyhow::Error> {
        Fetcher::new(self.into()).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser, error::ErrorKind};

    #[test]
    fn authentication_conflicts() {
        ClientArguments::command().debug_assert();
        let methods: [&[&str]; 3] = [
            &["--fetch-bearer-token", "secret"],
            &["--fetch-auth-header", "x-api-key: secret"],
            &["--fetch-username", "user", "--fetch-password", "secret"],
        ];
        for mask in 1u32..8 {
            let mut args = vec!["test"];
            for (i, method) in methods.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    args.extend_from_slice(method);
                }
            }
            let result = ClientArguments::try_parse_from(args);
            if mask.count_ones() == 1 {
                let args = result.unwrap();
                assert!(!format!("{args:?}").contains("secret"));
            } else {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::ArgumentConflict);
            }
        }
        for flag in ["--fetch-username", "--fetch-password"] {
            assert_eq!(
                ClientArguments::try_parse_from(["test", flag, "secret"])
                    .unwrap_err()
                    .kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
        assert!(ClientArguments::try_parse_from(["test"]).is_ok());
    }

    #[tokio::test]
    async fn malformed_header_is_rejected_without_echoing_secret() {
        for header in [
            "secret",
            " : secret",
            "invalid name: secret",
            "x-key: secret\nvalue",
        ] {
            let args =
                ClientArguments::try_parse_from(["test", "--fetch-auth-header", header]).unwrap();
            let error = args.new_fetcher().await.unwrap_err();
            assert!(!format!("{error:?}").contains("secret"));
        }
    }
}
