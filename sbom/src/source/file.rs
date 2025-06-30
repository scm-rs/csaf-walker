use crate::{
    discover::DiscoveredSbom,
    model::metadata::{self, SourceMetadata},
    retrieve::RetrievedSbom,
    source::Source,
    visitors::store::DIR_METADATA,
};
use anyhow::{Context, anyhow};
use bytes::Bytes;
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::SystemTime,
};
use time::OffsetDateTime;
use url::Url;
use walker_common::{
    retrieve::RetrievalMetadata,
    source::file::{read_sig_and_digests, to_path},
    utils::{self, openpgp::PublicKey},
    validate::source::{Key, KeySource, KeySourceError},
};

#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileOptions {
    pub since: Option<SystemTime>,
}

impl FileOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

/// A file-based source, possibly created by the [`crate::visitors::store::StoreVisitor`].
#[derive(Clone, Debug)]
pub struct FileSource {
    /// the path to the storage base, an absolute path
    base: PathBuf,
    options: FileOptions,
}

impl FileSource {
    pub fn new(
        base: impl AsRef<Path>,
        options: impl Into<Option<FileOptions>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base: fs::canonicalize(base)?,
            options: options.into().unwrap_or_default(),
        })
    }

    async fn scan_keys(&self) -> Result<Vec<metadata::Key>, anyhow::Error> {
        let dir = self.base.join(DIR_METADATA).join("keys");

        let mut result = Vec::new();

        let mut entries = match tokio::fs::read_dir(&dir).await {
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(result);
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("Failed scanning for keys: {}", dir.display()));
            }
            Ok(entries) => entries,
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            #[allow(clippy::single_match)]
            match path
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.rsplit_once('.'))
            {
                Some((name, "txt")) => result.push(metadata::Key {
                    fingerprint: Some(name.to_string()),
                    url: Url::from_file_path(&path).map_err(|()| {
                        anyhow!("Failed to build file URL for: {}", path.display())
                    })?,
                }),
                Some((_, _)) | None => {}
            }
        }

        Ok(result)
    }
}

impl walker_common::source::Source for FileSource {
    type Error = anyhow::Error;
    type Retrieved = RetrievedSbom;
}

impl Source for FileSource {
    async fn load_metadata(&self) -> Result<SourceMetadata, Self::Error> {
        let metadata = self.base.join(DIR_METADATA).join("metadata.json");
        let file = fs::File::open(&metadata)
            .with_context(|| format!("Failed to open file: {}", metadata.display()))?;

        let mut metadata: SourceMetadata =
            serde_json::from_reader(&file).context("Failed to read stored provider metadata")?;

        metadata.keys = self.scan_keys().await?;

        Ok(metadata)
    }

    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error> {
        const SKIP: &[&str] = &[".asc", ".sha256", ".sha512"];

        log::info!("Loading index - since: {:?}", self.options.since);

        let mut entries = tokio::fs::read_dir(&self.base).await?;
        let mut result = vec![];

        'entry: while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|s| s.to_str()) {
                Some(name) => name,
                None => continue,
            };

            for ext in SKIP {
                if name.ends_with(ext) {
                    log::debug!("Skipping file: {name}");
                    continue 'entry;
                }
            }

            if let Some(since) = self.options.since {
                let modified = path.metadata()?.modified()?;
                if modified < since {
                    log::debug!("Skipping file due to modification constraint: {modified:?}");
                    continue;
                }
            }

            let url = Url::from_file_path(&path)
                .map_err(|()| anyhow!("Failed to convert to URL: {}", path.display()))?;

            let modified = path.metadata()?.modified()?;

            result.push(DiscoveredSbom { url, modified })
        }

        Ok(result)
    }

    async fn load_sbom(&self, discovered: DiscoveredSbom) -> Result<RetrievedSbom, Self::Error> {
        let path = discovered
            .url
            .to_file_path()
            .map_err(|()| anyhow!("Unable to convert URL into path: {}", discovered.url))?;

        let data = Bytes::from(tokio::fs::read(&path).await?);

        let (signature, sha256, sha512) = read_sig_and_digests(&path, &data).await?;

        let last_modification = path
            .metadata()
            .ok()
            .and_then(|md| md.modified().ok())
            .map(OffsetDateTime::from);

        Ok(RetrievedSbom {
            discovered,
            data,
            signature,
            sha256,
            sha512,
            metadata: RetrievalMetadata {
                last_modification,
                etag: None,
            },
        })
    }
}

impl KeySource for FileSource {
    type Error = anyhow::Error;

    async fn load_public_key(
        &self,
        key: Key<'_>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        let bytes = tokio::fs::read(to_path(key.url).map_err(KeySourceError::Source)?)
            .await
            .map_err(|err| KeySourceError::Source(err.into()))?;
        utils::openpgp::validate_keys(bytes.into(), key.fingerprint)
            .map_err(KeySourceError::OpenPgp)
    }
}
