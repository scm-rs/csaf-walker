use crate::{
    discover::DiscoveredSbom,
    model::metadata::SourceMetadata,
    retrieve::{RetrievalContext, RetrievedSbom, RetrievedVisitor},
    source::Source,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext},
};
use anyhow::Context;
use sequoia_openpgp::{Cert, armor::Kind, serialize::SerializeInto};
use std::{
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};
use tokio::fs;
use walker_common::{
    retrieve::RetrievalError,
    store::{Document, StoreError, store_document},
    utils::openpgp::PublicKey,
    validate::ValidationError,
};

pub const DIR_METADATA: &str = "metadata";

/// Stores all data so that it can be used as a [`crate::source::Source`] later.
#[non_exhaustive]
pub struct StoreVisitor {
    /// the output base
    pub base: PathBuf,

    /// whether to set the file modification timestamps
    pub no_timestamps: bool,

    /// whether to store additional metadata (like the etag) using extended attributes
    pub no_xattrs: bool,
}

impl StoreVisitor {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            no_timestamps: false,
            no_xattrs: false,
        }
    }

    pub fn no_timestamps(mut self, no_timestamps: bool) -> Self {
        self.no_timestamps = no_timestamps;
        self
    }

    pub fn no_xattrs(mut self, no_xattrs: bool) -> Self {
        self.no_xattrs = no_xattrs;
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreRetrievedError<S: Source> {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError<DiscoveredSbom, S>),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreValidatedError<S: Source> {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Validation(#[from] ValidationError<S>),
}

impl<S: Source> RetrievedVisitor<S> for StoreVisitor {
    type Error = StoreRetrievedError<S>;
    type Context = ();

    async fn visit_context(
        &self,
        context: &RetrievalContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.store_keys(context.keys).await?;
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedSbom, RetrievalError<DiscoveredSbom, S>>,
    ) -> Result<(), Self::Error> {
        self.store(&result?).await?;
        Ok(())
    }
}

impl<S: Source> ValidatedVisitor<S> for StoreVisitor {
    type Error = StoreValidatedError<S>;
    type Context = ();

    async fn visit_context(
        &self,
        context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.store_keys(context.retrieval.keys).await?;
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        self.store(&result?.retrieved).await?;
        Ok(())
    }
}

impl StoreVisitor {
    async fn store_provider_metadata(&self, metadata: &SourceMetadata) -> Result<(), StoreError> {
        let metadir = self.base.join(DIR_METADATA);

        fs::create_dir(&metadir)
            .await
            .or_else(|err| match err.kind() {
                ErrorKind::AlreadyExists => Ok(()),
                _ => Err(err),
            })
            .with_context(|| format!("Failed to create metadata directory: {}", metadir.display()))
            .map_err(StoreError::Io)?;

        let file = metadir.join("metadata.json");
        let mut out = std::fs::File::create(&file)
            .with_context(|| {
                format!(
                    "Unable to open provider metadata file for writing: {}",
                    file.display()
                )
            })
            .map_err(StoreError::Io)?;
        serde_json::to_writer_pretty(&mut out, metadata)
            .context("Failed serializing provider metadata")
            .map_err(StoreError::Io)?;
        Ok(())
    }

    async fn store_keys(&self, keys: &[PublicKey]) -> Result<(), StoreError> {
        let metadata = self.base.join(DIR_METADATA).join("keys");
        fs::create_dir(&metadata)
            .await
            // ignore if the directory already exists
            .or_else(|err| match err.kind() {
                ErrorKind::AlreadyExists => Ok(()),
                _ => Err(err),
            })
            .with_context(|| {
                format!(
                    "Failed to create metadata directory: {}",
                    metadata.display()
                )
            })
            .map_err(StoreError::Io)?;

        for cert in keys.iter().flat_map(|k| &k.certs) {
            log::info!("Storing key: {}", cert.fingerprint());
            self.store_cert(cert, &metadata).await?;
        }

        Ok(())
    }

    async fn store_cert(&self, cert: &Cert, path: &Path) -> Result<(), StoreError> {
        let name = path.join(format!("{}.txt", cert.fingerprint().to_hex()));

        let data = Self::serialize_key(cert).map_err(StoreError::SerializeKey)?;

        fs::write(&name, data)
            .await
            .with_context(|| format!("Failed to store key: {}", name.display()))
            .map_err(StoreError::Io)?;
        Ok(())
    }

    fn serialize_key(cert: &Cert) -> Result<Vec<u8>, anyhow::Error> {
        let mut writer = sequoia_openpgp::armor::Writer::new(Vec::new(), Kind::PublicKey)?;
        writer.write_all(&cert.to_vec()?)?;
        Ok(writer.finalize()?)
    }

    async fn store(&self, sbom: &RetrievedSbom) -> Result<(), StoreError> {
        log::info!(
            "Storing: {} (modified: {:?})",
            sbom.url,
            sbom.metadata.last_modification
        );

        let file = PathBuf::from(sbom.url.path())
            .file_name()
            .map(|file| self.base.join(file))
            .ok_or_else(|| StoreError::Filename(sbom.url.to_string()))?;

        log::debug!("Writing {}", file.display());

        store_document(
            &file,
            Document {
                data: &sbom.data,
                changed: sbom.modified,
                metadata: &sbom.metadata,
                sha256: &sbom.sha256,
                sha512: &sbom.sha512,
                signature: &sbom.signature,
                no_timestamps: self.no_timestamps,
                no_xattrs: self.no_xattrs,
            },
        )
        .await?;

        Ok(())
    }
}
