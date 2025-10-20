use anyhow::bail;
use bytes::Bytes;
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};
use url::Url;

#[cfg(feature = "s3")]
use aws_config::{BehaviorVersion, Region, meta::region::RegionProviderChain};
#[cfg(feature = "s3")]
use aws_sdk_s3::{
    Client,
    config::{AppName, Credentials},
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    Path(PathBuf),
    Http(Url),
    #[cfg(feature = "s3")]
    S3(S3),
}

impl TryFrom<&str> for Source {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.starts_with("http://") || value.starts_with("https://") {
            return Ok(Self::Http(Url::parse(value)?));
        }

        #[cfg(feature = "s3")]
        if value.starts_with("s3://") {
            return Ok(Self::S3(S3::try_from(value)?));
        }
        #[cfg(not(feature = "s3"))]
        if value.starts_with("s3://") {
            bail!("S3 URLs are not supported");
        }

        Ok(Self::Path(value.into()))
    }
}

impl Source {
    pub async fn discover(self) -> anyhow::Result<Vec<Self>> {
        match self {
            Self::Path(path) => Ok(Self::discover_path(path)?
                .into_iter()
                .map(Self::Path)
                .collect()),
            #[cfg(feature = "s3")]
            Self::S3(s3) if s3.key.is_none() => Ok(Self::discover_s3(s3)
                .await?
                .into_iter()
                .map(Self::S3)
                .collect()),
            value => Ok(vec![value]),
        }
    }

    fn discover_path(path: PathBuf) -> anyhow::Result<Vec<PathBuf>> {
        log::debug!("Discovering: {}", path.display());

        if !path.exists() {
            bail!("{} does not exist", path.display());
        } else if path.is_file() {
            log::debug!("Is a file");
            Ok(vec![path])
        } else if path.is_dir() {
            log::debug!("Is a directory");
            let mut result = Vec::new();

            for path in walkdir::WalkDir::new(path).into_iter() {
                let path = path?;
                if path.file_type().is_file() {
                    result.push(path.path().to_path_buf());
                }
            }

            Ok(result)
        } else {
            log::warn!("Is something unknown: {}", path.display());
            Ok(vec![])
        }
    }

    #[cfg(feature = "s3")]
    async fn discover_s3(s3: S3) -> anyhow::Result<Vec<S3>> {
        let client = s3.client().await?;

        let mut response = client
            .list_objects_v2()
            .bucket(s3.bucket.clone())
            .max_keys(100)
            .into_paginator()
            .send();

        let mut result = vec![];
        while let Some(next) = response.next().await {
            let next = next?;
            for object in next.contents() {
                if let Some(key) = object.key.clone() {
                    result.push(key);
                }
            }
        }

        Ok(result
            .into_iter()
            .map(|key| S3 {
                key: Some(key),
                ..(s3.clone())
            })
            .collect())
    }

    pub fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Path(path) => path.to_string_lossy(),
            Self::Http(url) => url.as_str().into(),
            #[cfg(feature = "s3")]
            Self::S3(s3) => format!(
                "s3://{}/{}/{}",
                s3.region,
                s3.bucket,
                s3.key.as_deref().unwrap_or_default()
            )
            .into(),
        }
    }

    /// Load the content of the source
    pub async fn load(&self) -> Result<Bytes, anyhow::Error> {
        Ok(match self {
            Self::Path(path) => tokio::fs::read(path).await?.into(),
            Self::Http(url) => {
                reqwest::get(url.clone())
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?
            }
            #[cfg(feature = "s3")]
            Self::S3(s3) => {
                let client = s3.client();
                client
                    .await?
                    .get_object()
                    .key(s3.key.clone().unwrap_or_default())
                    .bucket(s3.bucket.clone())
                    .send()
                    .await?
                    .body
                    .collect()
                    .await?
                    .into_bytes()
            }
        })
    }

    /// Delete the source
    pub async fn delete(&self) -> anyhow::Result<()> {
        match self {
            Self::Path(file) => {
                // just delete the file
                tokio::fs::remove_file(&file).await?;
            }
            Self::Http(url) => {
                // issue a DELETE request
                reqwest::Client::builder()
                    .build()?
                    .delete(url.clone())
                    .send()
                    .await?;
            }
            #[cfg(feature = "s3")]
            Self::S3(s3) => {
                // delete the object from the bucket
                let client = s3.client();
                client
                    .await?
                    .delete_object()
                    .key(s3.key.clone().unwrap_or_default())
                    .bucket(s3.bucket.clone())
                    .send()
                    .await?;
            }
        }

        Ok(())
    }

    /// move the source
    ///
    /// NOTE: This is a no-op for HTTP sources.
    pub async fn r#move(&self, path: &str) -> anyhow::Result<()> {
        match self {
            Self::Path(file) => {
                let path = Path::new(&path);
                tokio::fs::create_dir_all(path).await?;
                tokio::fs::copy(&file, path.join(file)).await?;
                tokio::fs::remove_file(&file).await?;
            }
            Self::Http(url) => {
                // no-op, but warn
                log::warn!("Unable to move HTTP source ({url}), skipping!");
            }
            #[cfg(feature = "s3")]
            Self::S3(s3) => {
                let client = s3.client();
                client
                    .await?
                    .copy_object()
                    .copy_source(s3.key.clone().unwrap_or_default())
                    .key(format!("{path}/{}", s3.key.as_deref().unwrap_or_default()))
                    .bucket(s3.bucket.clone())
                    .send()
                    .await?;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "s3")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3 {
    region: String,
    credentials: Option<(String, String)>,
    bucket: String,
    key: Option<String>,
}

#[cfg(feature = "s3")]
impl TryFrom<&str> for S3 {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let uri = fluent_uri::Uri::try_from(value)?;

        let Some(auth) = uri.authority() else {
            bail!("Missing authority");
        };

        let path = uri.path().to_string();
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            bail!("Missing bucket");
        }

        let (bucket, key) = match path.split_once('/') {
            Some((bucket, key)) => (bucket.to_string(), Some(key.to_string())),
            None => (path.to_string(), None),
        };

        let region = auth.host().to_string();

        let credentials = auth.userinfo().and_then(|userinfo| {
            userinfo
                .split_once(':')
                .map(|(username, password)| (username.to_string(), password.to_string()))
        });

        Ok(S3 {
            region,
            credentials,
            bucket,
            key,
        })
    }
}

#[cfg(feature = "s3")]
impl S3 {
    pub async fn client(&self) -> anyhow::Result<Client> {
        let region_provider = RegionProviderChain::first_try(Region::new(self.region.clone()));

        let mut shared_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .app_name(AppName::new(crate::USER_AGENT)?);

        if let Some((key_id, access_key)) = &self.credentials {
            let credentials = Credentials::new(key_id, access_key, None, None, "config");
            shared_config = shared_config.credentials_provider(credentials);
        }

        let shared_config = shared_config.load().await;

        Ok(Client::new(&shared_config))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "s3")]
    #[test]
    fn parse_s3() {
        assert_eq!(
            S3 {
                region: "us-east-1".to_string(),
                credentials: None,
                bucket: "b1".to_string(),
                key: None,
            },
            S3::try_from("s3://us-east-1/b1").unwrap()
        );
        assert_eq!(
            S3 {
                region: "us-east-1".to_string(),
                credentials: Some(("foo".to_string(), "bar".to_string())),
                bucket: "b1".to_string(),
                key: None,
            },
            S3::try_from("s3://foo:bar@us-east-1/b1").unwrap()
        );
        assert_eq!(
            S3 {
                region: "us-east-1".to_string(),
                credentials: Some(("foo".to_string(), "bar".to_string())),
                bucket: "b1".to_string(),
                key: Some("path/to/file".to_string()),
            },
            S3::try_from("s3://foo:bar@us-east-1/b1/path/to/file").unwrap()
        );
    }

    #[cfg(feature = "s3")]
    #[test]
    fn parse_s3_custom_region() {
        assert_eq!(
            S3 {
                region: "my.own.endpoint".to_string(),
                credentials: None,
                bucket: "b1".to_string(),
                key: None,
            },
            S3::try_from("s3://my.own.endpoint/b1").unwrap()
        );
        assert_eq!(
            S3 {
                region: "my.own.endpoint".to_string(),
                credentials: Some(("foo".to_string(), "bar".to_string())),
                bucket: "b1".to_string(),
                key: None,
            },
            S3::try_from("s3://foo:bar@my.own.endpoint/b1").unwrap()
        );
        assert_eq!(
            S3 {
                region: "my.own.endpoint".to_string(),
                credentials: Some(("foo".to_string(), "bar".to_string())),
                bucket: "b1".to_string(),
                key: Some("path/to/file".to_string()),
            },
            S3::try_from("s3://foo:bar@my.own.endpoint/b1/path/to/file").unwrap()
        );
    }
}
