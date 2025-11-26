use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
use reqwest::{Body, Method, StatusCode, Url, header};
use std::time::Duration;
use walker_common::{
    http::get_retry_after_from_response_header,
    sender::{self, HttpSender},
};

#[cfg(feature = "sbom-walker")]
mod sbom;
#[cfg(feature = "sbom-walker")]
pub use sbom::*;

#[cfg(feature = "csaf-walker")]
mod csaf;
#[cfg(feature = "csaf-walker")]
pub use csaf::*;

#[cfg(feature = "clap")]
mod clap;
#[cfg(feature = "clap")]
pub use self::clap::*;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Sender(#[from] sender::Error),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error("client error: {0}")]
    Client(StatusCode),
    #[error("server error: {0}")]
    Server(StatusCode),
    #[error("unexpected status: {0}")]
    UnexpectedStatus(StatusCode),
    #[error("Rate limited (HTTP 429), retry after {0:?}")]
    RateLimited(Duration),
}

/// Send data to a remote sink.
#[non_exhaustive]
#[derive(Clone)]
pub struct SendVisitor {
    /// The target endpoint
    pub url: Url,

    /// The HTTP client to use
    pub sender: HttpSender,

    /// The number of retries in case of a server or transmission failure
    pub retries: usize,

    /// The minimum delay between retries
    pub min_delay: Option<Duration>,

    /// The maximum delay between retries
    pub max_delay: Option<Duration>,

    /// The default retry-after duration when a 429 response doesn't include a Retry-After header
    pub default_retry_after: Option<Duration>,
}

impl SendVisitor {
    pub fn new(url: impl Into<Url>, sender: HttpSender) -> Self {
        Self {
            url: url.into(),
            sender,
            retries: 0,
            min_delay: None,
            max_delay: None,
            default_retry_after: Some(Duration::from_secs(10)),
        }
    }

    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn min_delay(mut self, retry_delay: impl Into<Duration>) -> Self {
        self.min_delay = Some(retry_delay.into());
        self
    }

    pub fn max_delay(mut self, retry_delay: impl Into<Duration>) -> Self {
        self.max_delay = Some(retry_delay.into());
        self
    }

    /// Set the default retry-after duration when a 429 response doesn't include a Retry-After header.
    pub fn default_retry_after(mut self, duration: impl Into<Duration>) -> Self {
        self.default_retry_after = Some(duration.into());
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendOnceError {
    #[error(transparent)]
    Temporary(SendError),
    #[error(transparent)]
    Permanent(SendError),
}

impl From<SendOnceError> for SendError {
    fn from(value: SendOnceError) -> Self {
        match value {
            SendOnceError::Temporary(e) => e,
            SendOnceError::Permanent(e) => e,
        }
    }
}

impl SendVisitor {
    /// Send request once
    async fn send_once<F>(
        &self,
        name: &str,
        data: Bytes,
        customizer: F,
    ) -> Result<(), SendOnceError>
    where
        F: FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let request = self
            .sender
            .request(Method::POST, self.url.clone())
            .await
            .map_err(|err| SendOnceError::Temporary(err.into()))?
            .body(Body::from(data));
        let request = customizer(request);
        let response = request
            .send()
            .await
            .map_err(|err| SendOnceError::Temporary(err.into()))?;

        if let Some(retry_after) = get_retry_after_from_response_header(
            &response,
            self.default_retry_after.unwrap_or(Duration::from_secs(10)),
        ) {
            log::warn!(
                "Rate limited (429) when uploading {name}, retry after: {:?}",
                retry_after
            );
            return Err(SendOnceError::Temporary(SendError::RateLimited(
                retry_after,
            )));
        }

        let status = response.status();

        if status.is_success() {
            log::debug!("Uploaded {} -> {}", name, response.status());
            Ok(())
        } else if status.is_client_error() {
            log::warn!("Failed to upload, payload rejected {name} -> {status}",);
            Err(SendOnceError::Permanent(SendError::Client(status)))
        } else if status.is_server_error() {
            log::warn!("Failed to upload, server error {name} -> {status}",);
            Err(SendOnceError::Temporary(SendError::Server(status)))
        } else {
            Err(SendOnceError::Permanent(SendError::UnexpectedStatus(
                status,
            )))
        }
    }

    /// Send request, retry in case of temporary errors
    async fn send<F>(&self, name: &str, data: Bytes, customizer: F) -> Result<(), SendError>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let mut retry = ExponentialBuilder::default();
        if self.retries > 0 {
            retry = retry.with_max_times(self.retries);
        }
        if let Some(min_delay) = self.min_delay {
            retry = retry.with_min_delay(min_delay);
        }
        if let Some(max_delay) = self.max_delay {
            retry = retry.with_max_delay(max_delay);
        }

        Ok(
            (|| async { self.send_once(name, data.clone(), &customizer).await })
                .retry(retry)
                .sleep(tokio::time::sleep)
                .when(|e| matches!(e, SendOnceError::Temporary(_)))
                .notify(|err, dur| {
                    // If rate limited, ensure we wait at least the Retry-After duration
                    if let SendOnceError::Temporary(SendError::RateLimited(retry_after)) = err {
                        if dur < *retry_after {
                            log::info!(
                                "Rate limited, extending wait from {:?} to {:?}",
                                dur,
                                retry_after
                            );
                            let additional = *retry_after - dur;
                            std::thread::sleep(additional);
                        }
                    }
                })
                .await?,
        )
    }
}
