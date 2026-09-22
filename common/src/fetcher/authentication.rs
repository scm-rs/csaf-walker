use base64::{Engine, prelude::BASE64_STANDARD};
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use std::fmt;

/// Static credentials applied to every request made by a fetcher.
#[derive(Clone)]
pub enum FetchAuthentication {
    /// Send `Authorization: Bearer <token>`.
    Bearer(String),
    /// Send a custom authentication header, for example `X-API-Key`.
    Header { name: String, value: String },
    /// Send HTTP Basic authentication. The password may be empty.
    Basic { username: String, password: String },
}

impl fmt::Debug for FetchAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bearer(_) => "Bearer([REDACTED])",
            Self::Header { .. } => "Header([REDACTED])",
            Self::Basic { .. } => "Basic([REDACTED])",
        })
    }
}

impl FetchAuthentication {
    pub(super) fn header(&self) -> anyhow::Result<(HeaderName, HeaderValue)> {
        let (name, value) = match self {
            Self::Bearer(token) => (AUTHORIZATION, format!("Bearer {token}")),
            Self::Header { name, value } => (
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| anyhow::anyhow!("Invalid fetch authentication header name"))?,
                value.clone(),
            ),
            Self::Basic { username, password } => {
                anyhow::ensure!(
                    !username.contains(':'),
                    "Basic authentication username must not contain ':'"
                );
                let encoded = BASE64_STANDARD.encode(format!("{username}:{password}"));
                (AUTHORIZATION, format!("Basic {encoded}"))
            }
        };
        let mut value = HeaderValue::from_str(&value)
            .map_err(|_| anyhow::anyhow!("Invalid fetch authentication header value"))?;
        value.set_sensitive(true);
        Ok((name, value))
    }
}
