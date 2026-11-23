//! Send data off to a remote API

pub mod provider;

mod error;
pub use error::*;

use crate::{
    USER_AGENT,
    sender::provider::{TokenInjector, TokenProvider},
};
use anyhow::Context;
use reqwest::{IntoUrl, Method, RequestBuilder, header};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct HttpSender {
    client: reqwest::Client,
    provider: Arc<dyn TokenProvider>,
    query_parameters: HashMap<String, String>,
}

/// Options for the [`HttpSender`].
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct HttpSenderOptions {
    pub connect_timeout: Option<Duration>,
    pub timeout: Option<Duration>,
    pub additional_root_certificates: Vec<PathBuf>,
    pub tls_insecure: bool,
    pub query_parameters: HashMap<String, String>,
}

impl HttpSenderOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn connect_timeout(mut self, connect_timeout: impl Into<Option<Duration>>) -> Self {
        self.connect_timeout = connect_timeout.into();
        self
    }

    pub fn timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.timeout = timeout.into();
        self
    }

    pub fn query_parameters<I>(mut self, query_parameters: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.query_parameters = HashMap::from_iter(query_parameters);
        self
    }

    pub fn add_query_parameters<I>(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.query_parameters.insert(key.into(), value.into());
        self
    }

    pub fn extend_query_parameters<I>(mut self, query_parameters: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.query_parameters.extend(query_parameters);
        self
    }

    pub fn additional_root_certificates<I>(mut self, additional_root_certificates: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.additional_root_certificates = Vec::from_iter(additional_root_certificates);
        self
    }

    pub fn add_additional_root_certificate(
        mut self,
        additional_root_certificate: impl Into<PathBuf>,
    ) -> Self {
        self.additional_root_certificates
            .push(additional_root_certificate.into());
        self
    }

    pub fn extend_additional_root_certificate<I>(mut self, additional_root_certificates: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.additional_root_certificates
            .extend(additional_root_certificates);
        self
    }

    pub fn tls_insecure(mut self, tls_insecure: bool) -> Self {
        self.tls_insecure = tls_insecure;
        self
    }
}

impl HttpSender {
    pub async fn new<P>(provider: P, options: HttpSenderOptions) -> Result<Self, anyhow::Error>
    where
        P: TokenProvider + 'static,
    {
        let mut headers = header::HeaderMap::new();
        headers.insert("User-Agent", header::HeaderValue::from_static(USER_AGENT));

        let mut client = reqwest::ClientBuilder::new().default_headers(headers);

        if let Some(connect_timeout) = options.connect_timeout {
            client = client.connect_timeout(connect_timeout);
        }

        if let Some(timeout) = options.timeout {
            client = client.timeout(timeout);
        }

        for cert in options.additional_root_certificates {
            let cert = std::fs::read(&cert)
                .with_context(|| format!("Reading certificate: {}", cert.display()))?;
            let cert = reqwest::tls::Certificate::from_pem(&cert)?;
            client = client.add_root_certificate(cert);
        }

        if options.tls_insecure {
            log::warn!("Disabling TLS validation");
            client = client
                .danger_accept_invalid_hostnames(true)
                .danger_accept_invalid_certs(true);
        }

        Ok(Self {
            client: client.build()?,
            provider: Arc::new(provider),
            query_parameters: options.query_parameters,
        })
    }

    /// build a new request, injecting the token
    pub async fn request<U: IntoUrl>(
        &self,
        method: Method,
        url: U,
    ) -> Result<RequestBuilder, Error> {
        self.client
            .request(method, url)
            .query(
                &self
                    .query_parameters
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<(String, String)>>(),
            )
            .inject_token(&self.provider)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_are_independent() {
        let options = HttpSenderOptions::default()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300));

        assert_eq!(options.connect_timeout, Some(Duration::from_secs(15)));
        assert_eq!(options.timeout, Some(Duration::from_secs(300)));
    }
}
