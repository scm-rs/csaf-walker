use crate::model::metadata::ProviderMetadata;
use async_trait::async_trait;
use hickory_resolver::Resolver;
use sectxtlib::SecurityTxt;
use std::fmt::Debug;
use url::Url;
use walker_common::fetcher::{self, Fetcher, Json};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse security.txt: {0}")]
    SecurityTxt(#[from] sectxtlib::ParseError),
    #[error("failed to fetch: {0}")]
    Fetch(#[from] fetcher::Error),
    #[error("unable to discover metadata")]
    NotFound,
    #[error("DNS request failed: {0}")]
    Dns(#[from] hickory_resolver::net::NetError),
}

#[async_trait(?Send)]
pub trait MetadataSource: Debug {
    async fn load_metadata(&self, fetcher: &Fetcher) -> Result<ProviderMetadata, Error>;
}

#[async_trait(?Send)]
impl MetadataSource for Url {
    async fn load_metadata(&self, fetcher: &Fetcher) -> Result<ProviderMetadata, Error> {
        Ok(fetcher
            .fetch::<Json<ProviderMetadata>>(self.clone())
            .await?
            .into_inner())
    }
}

#[async_trait(?Send)]
impl MetadataSource for &str {
    async fn load_metadata(&self, fetcher: &Fetcher) -> Result<ProviderMetadata, Error> {
        MetadataRetriever::new(*self).load_metadata(fetcher).await
    }
}

#[async_trait(?Send)]
impl MetadataSource for String {
    async fn load_metadata(&self, fetcher: &Fetcher) -> Result<ProviderMetadata, Error> {
        MetadataRetriever::new(self).load_metadata(fetcher).await
    }
}

/// A metadata source implementing the CSAF metadata discovery process.
#[derive(Clone, Debug)]
pub struct MetadataRetriever {
    pub base_url: String,
}

impl MetadataRetriever {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Fetch a security.txt and extract all CSAF entries.
    ///
    /// In order for a CSAF entry to be considered, it needs to have a scheme of `https` and parse
    /// as a URL.
    pub async fn get_metadata_url_from_security_text(
        fetcher: &Fetcher,
        host_url: String,
    ) -> Result<Option<Url>, Error> {
        // if we fail to retrieve the `security.txt` other than by a 404, we fail
        let Some(text) = fetcher.fetch::<Option<String>>(host_url).await? else {
            return Ok(None);
        };

        // parse as security.txt and extract the CSAF entry
        // as of now, we only take the first valid one

        let text = SecurityTxt::parse(&text)?;
        let url = text
            .extension
            .into_iter()
            .filter(|ext| ext.name == "csaf")
            .filter_map(|ext| Url::parse(&ext.value).ok())
            .find(|url| url.scheme() == "https");

        if url.is_none() {
            log::info!("No CSAF information is existing security.txt");
        }

        Ok(url)
    }

    /// Treat the source as a URL and try to retrieve it
    ///
    /// If the source is not a URL, we consider it "not found".
    /// If the URL parses but cannot be found, that's an error.
    pub async fn approach_full_url(
        &self,
        fetcher: &Fetcher,
    ) -> Result<Option<ProviderMetadata>, Error> {
        let Ok(url) = Url::parse(&self.base_url) else {
            return Ok(None);
        };

        Ok(Some(
            fetcher
                .fetch::<Json<ProviderMetadata>>(url)
                .await?
                .into_inner(),
        ))
    }

    /// Retrieve provider metadata through the full well-known URL.
    ///
    /// If retrieving the constructed URL returns a 404, we succeed with `Ok(None)`.
    pub async fn approach_well_known(
        &self,
        fetcher: &Fetcher,
    ) -> Result<Option<ProviderMetadata>, Error> {
        let url = format!(
            "https://{}/.well-known/csaf/provider-metadata.json",
            self.base_url,
        );

        log::debug!("Trying to retrieve by well-known approach: {url}");

        Ok(fetcher
            .fetch::<Option<Json<ProviderMetadata>>>(url)
            .await?
            .map(|metadata| metadata.into_inner()))
    }

    /// Retrieve provider metadata through the DNS path of provided URL.
    ///
    /// As it is hard to detect a "host not found" error, compared to any other connection error,
    /// we do a DNS pre-flight check. If the hostname resolves into an IP address, we assume the
    /// following HTTP request should not fail due to a "host not found" error.
    pub async fn approach_dns(&self, fetcher: &Fetcher) -> Result<Option<ProviderMetadata>, Error> {
        let host = format!("csaf.data.security.{}", self.base_url);

        log::debug!("Trying to retrieve by DNS approach: {host}");

        // DNS pre-flight check

        #[cfg(not(any(unix, target_os = "windows")))]
        let resolver = Resolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )?;
        #[cfg(any(unix, target_os = "windows"))]
        let resolver = Resolver::builder_tokio()?.build()?;

        match resolver.lookup_ip(&host).await {
            Ok(result) => {
                if result.iter().count() == 0 {
                    return Ok(None);
                }
            }
            Err(err) if err.is_no_records_found() => {
                return Ok(None);
            }
            Err(err) => {
                return Err(err.into());
            }
        }

        // fetch content

        let url = format!("https://{host}");

        Ok(fetcher
            .fetch::<Option<Json<ProviderMetadata>>>(url)
            .await?
            .map(|value| value.into_inner()))
    }

    /// Retrieving provider metadata via the security text from the provided URL.
    ///
    /// This takes the source as domain, and the provided path to compose a URL. If the security.txt
    /// cannot be found or doesn't contain a valid CSAF entry, it will return `Ok(None)`.
    pub async fn approach_security_txt(
        &self,
        fetcher: &Fetcher,
        path: &str,
    ) -> Result<Option<ProviderMetadata>, Error> {
        let url = format!("https://{}/{path}", self.base_url);

        log::debug!("Trying to retrieve by security.txt approach: {url}");

        if let Some(url) = Self::get_metadata_url_from_security_text(fetcher, url).await? {
            // if we fail with a 404, that's an error too, as the security.txt pointed to us towards it
            Ok(Some(
                fetcher
                    .fetch::<Json<ProviderMetadata>>(url)
                    .await?
                    .into_inner(),
            ))
        } else {
            Ok(None)
        }
    }
}

#[async_trait(?Send)]
impl MetadataSource for MetadataRetriever {
    async fn load_metadata(&self, fetcher: &Fetcher) -> Result<ProviderMetadata, Error> {
        // try a full URL first

        if let Some(metadata) = self.approach_full_url(fetcher).await? {
            return Ok(metadata);
        }

        // from here on we are following "7.3.1 Finding provider-metadata.json"
        // see: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#731-finding-provider-metadatajson

        // well-known approach

        if let Some(metadata) = self.approach_well_known(fetcher).await? {
            return Ok(metadata);
        }

        // new security.txt location

        if let Some(metadata) = self
            .approach_security_txt(fetcher, ".well-known/security.txt")
            .await?
        {
            return Ok(metadata);
        }

        // legacy security.txt location

        if let Some(metadata) = self.approach_security_txt(fetcher, "security.txt").await? {
            return Ok(metadata);
        }

        // DNS approach

        if let Some(metadata) = self.approach_dns(fetcher).await? {
            return Ok(metadata);
        }

        // we could not find any metadata

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use walker_common::fetcher::FetcherOptions;

    #[tokio::test]
    async fn test_dns_fail() {
        let fetcher = Fetcher::new(FetcherOptions::default()).await.unwrap();

        let retriever = MetadataRetriever::new("this-should-not-exist");
        let result = retriever.approach_dns(&fetcher).await.unwrap();

        assert!(result.is_none());
    }

    /// Test a valid DNS case.
    ///
    /// We can't just enable this test, as we don't control this setup, it might break at
    /// any moment.
    #[ignore]
    #[tokio::test]
    async fn test_dns_success() {
        let fetcher = Fetcher::new(FetcherOptions::default()).await.unwrap();

        let retriever = MetadataRetriever::new("nozominetworks.com");
        let result = retriever.approach_dns(&fetcher).await.unwrap();

        assert!(result.is_some());
    }
}
