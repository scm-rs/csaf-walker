use crate::{
    discover::{DiscoveredAdvisory, DistributionContext},
    metadata::{self, MetadataSource},
    model::metadata::ProviderMetadata,
    retrieve::RetrievedAdvisory,
    rolie::{RolieSource, SourceFile},
    source::Source,
};
use bytes::{BufMut, Bytes, BytesMut};
use digest::Digest;
use futures::try_join;
use reqwest::Response;
use sha2::{Sha256, Sha512};
use std::{sync::Arc, time::SystemTime};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use url::{ParseError, Url};
use walker_common::utils::url::ensure_slash;
use walker_common::{
    changes::{self, ChangeEntry, ChangeSource},
    fetcher::{self, DataProcessor, Fetcher},
    retrieve::{RetrievalMetadata, RetrievedDigest, RetrievingDigest},
    utils::openpgp::PublicKey,
    validate::source::{Key, KeySource, KeySourceError},
};

#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpOptions {
    pub since: Option<SystemTime>,
}

impl HttpOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

#[derive(Clone, Debug)]
pub struct HttpSource {
    fetcher: Fetcher,
    metadata_source: Arc<dyn MetadataSource>,
    options: HttpOptions,
}

impl HttpSource {
    pub fn new<M: MetadataSource + 'static>(
        metadata: M,
        fetcher: Fetcher,
        options: HttpOptions,
    ) -> Self {
        Self {
            metadata_source: Arc::new(metadata),
            fetcher,
            options,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpSourceError {
    #[error("Metadata discovery error: {0}")]
    Metadata(#[from] metadata::Error),
    #[error("Fetch error: {0}")]
    Fetcher(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<changes::Error> for HttpSourceError {
    fn from(value: changes::Error) -> Self {
        match value {
            changes::Error::Fetcher(err) => Self::Fetcher(err),
            changes::Error::Url(err) => Self::Url(err),
            changes::Error::Csv(err) => Self::Csv(err),
        }
    }
}

impl walker_common::source::Source for HttpSource {
    type Error = HttpSourceError;
    type Retrieved = RetrievedAdvisory;
}

impl Source for HttpSource {
    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        Ok(self.metadata_source.load_metadata(&self.fetcher).await?)
    }

    async fn load_index(
        &self,
        context: DistributionContext,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error> {
        let discover_context = Arc::new(context);

        // filter out advisories based on since, but only if we can be sure
        let since_filter = |advisory: &Result<_, _>| match (advisory, &self.options.since) {
            (
                Ok(DiscoveredAdvisory {
                    url: _,
                    context: _,
                    digest: _,
                    signature: _,
                    modified,
                }),
                Some(since),
            ) => modified >= since,
            _ => true,
        };

        match discover_context.as_ref() {
            DistributionContext::Directory(base) => {
                let base = ensure_slash(base.clone());
                let changes = ChangeSource::retrieve(&self.fetcher, &base).await?;

                Ok(changes
                    .entries
                    .into_iter()
                    .map(|ChangeEntry { file, timestamp }| {
                        let modified = timestamp.into();
                        let url = base.join(&file)?;

                        Ok::<_, ParseError>(DiscoveredAdvisory {
                            context: discover_context.clone(),
                            url,
                            modified,
                            signature: None,
                            digest: None,
                        })
                    })
                    .filter(since_filter)
                    .collect::<Result<_, _>>()?)
            }

            DistributionContext::Feed(feed) => {
                let source_files = RolieSource::retrieve(&self.fetcher, feed.clone()).await?;
                Ok(source_files
                    .files
                    .into_iter()
                    .map(
                        |SourceFile {
                             file,
                             timestamp,
                             digest,
                             signature,
                         }| {
                            let modified = timestamp.into();
                            let url = Url::parse(&file)?;
                            let digest = digest.map(|digest| Url::parse(&digest)).transpose()?;
                            let signature = signature
                                .map(|signature| Url::parse(&signature))
                                .transpose()?;

                            Ok::<_, ParseError>(DiscoveredAdvisory {
                                context: discover_context.clone(),
                                url,
                                digest,
                                signature,
                                modified,
                            })
                        },
                    )
                    .filter(since_filter)
                    .collect::<Result<_, _>>()?)
            }
        }
    }

    async fn load_advisory(
        &self,
        discovered: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error> {
        let digest_result = try_join!(
            async {
                // If we have a signature source, use it. Otherwise, guess.
                match discovered.signature.clone() {
                    Some(signature) => self.fetcher.fetch::<Option<String>>(signature).await,
                    None => {
                        self.fetcher
                            .fetch::<Option<String>>(format!("{url}.asc", url = discovered.url))
                            .await
                    }
                }
            },
            async {
                match discovered.digest.clone() {
                    Some(digest) if digest.as_str().ends_with(".sha256") => {
                        self.fetcher.fetch::<Option<String>>(digest).await
                    }
                    Some(_) => Ok(None),
                    None => {
                        self.fetcher
                            .fetch::<Option<String>>(format!("{url}.sha256", url = discovered.url))
                            .await
                    }
                }
            },
            async {
                match discovered.digest.clone() {
                    Some(digest) if digest.as_str().ends_with(".sha512") => {
                        self.fetcher.fetch::<Option<String>>(digest).await
                    }
                    Some(_) => Ok(None),
                    None => {
                        self.fetcher
                            .fetch::<Option<String>>(format!("{url}.sha512", url = discovered.url))
                            .await
                    }
                }
            },
        );

        let (signature, sha256, sha512) = digest_result.map_err(HttpSourceError::Fetcher)?;

        let sha256 = sha256
            // take the first "word" from the line
            .and_then(|expected| expected.split(' ').next().map(ToString::to_string))
            .map(|expected| RetrievingDigest {
                expected,
                current: Sha256::new(),
            });
        let sha512 = sha512
            // take the first "word" from the line
            .and_then(|expected| expected.split(' ').next().map(ToString::to_string))
            .map(|expected| RetrievingDigest {
                expected,
                current: Sha512::new(),
            });

        let advisory = self
            .fetcher
            .fetch_processed(
                discovered.url.clone(),
                FetchingRetrievedAdvisory { sha256, sha512 },
            )
            .await?;

        Ok(advisory.into_retrieved(discovered, signature))
    }
}

pub struct FetchedRetrievedAdvisory {
    data: Bytes,
    sha256: Option<RetrievedDigest<Sha256>>,
    sha512: Option<RetrievedDigest<Sha512>>,
    metadata: RetrievalMetadata,
}

impl FetchedRetrievedAdvisory {
    fn into_retrieved(
        self,
        discovered: DiscoveredAdvisory,
        signature: Option<String>,
    ) -> RetrievedAdvisory {
        RetrievedAdvisory {
            discovered,
            data: self.data,
            signature,
            sha256: self.sha256,
            sha512: self.sha512,
            metadata: self.metadata,
        }
    }
}

pub struct FetchingRetrievedAdvisory {
    pub sha256: Option<RetrievingDigest<Sha256>>,
    pub sha512: Option<RetrievingDigest<Sha512>>,
}

impl DataProcessor for FetchingRetrievedAdvisory {
    type Type = FetchedRetrievedAdvisory;

    async fn process(&self, response: Response) -> Result<Self::Type, reqwest::Error> {
        let mut response = response.error_for_status()?;

        let mut data = BytesMut::new();
        let mut sha256 = self.sha256.clone();
        let mut sha512 = self.sha512.clone();

        while let Some(chunk) = response.chunk().await? {
            if let Some(d) = &mut sha256 {
                d.update(&chunk);
            }
            if let Some(d) = &mut sha512 {
                d.update(&chunk);
            }
            data.put(chunk);
        }

        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|s| s.to_str().ok())
            .map(ToString::to_string);

        let last_modification = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| OffsetDateTime::parse(s, &Rfc2822).ok());

        Ok(FetchedRetrievedAdvisory {
            data: data.freeze(),
            sha256: sha256.map(|d| d.into()),
            sha512: sha512.map(|d| d.into()),
            metadata: RetrievalMetadata {
                last_modification,
                etag,
            },
        })
    }
}

impl KeySource for HttpSource {
    type Error = fetcher::Error;

    async fn load_public_key(
        &self,
        key_source: Key<'_>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        self.fetcher.load_public_key(key_source).await
    }
}
