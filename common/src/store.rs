use crate::retrieve::{RetrievalMetadata, RetrievedDigest};
use anyhow::Context;
use sha2::{Sha256, Sha512};
use std::{path::Path, time::SystemTime};
use tokio::fs;

pub const ATTR_ETAG: &str = "etag";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0:#}")]
    Io(anyhow::Error),
    #[error("Failed to construct filename from URL: {0}")]
    Filename(String),
    #[error("Serialize key error: {0:#}")]
    SerializeKey(anyhow::Error),
}

pub struct Document<'a> {
    /// The data to store
    pub data: &'a [u8],
    /// An optional SHA256 digest
    pub sha256: &'a Option<RetrievedDigest<Sha256>>,
    /// An optional SHA512 digest
    pub sha512: &'a Option<RetrievedDigest<Sha512>>,
    /// An optional signature
    pub signature: &'a Option<String>,

    /// Last change date
    pub changed: SystemTime,

    /// Metadata from the retrieval process
    pub metadata: &'a RetrievalMetadata,

    pub no_timestamps: bool,
    pub no_xattrs: bool,
}

pub struct ErrorData<'a> {
    pub data: &'a [u8],
}

/// Stores retrieval errors to a file.
pub async fn store_errors(file: &Path, document: ErrorData<'_>) -> Result<(), StoreError> {
    log::debug!("Writing errors for {}", file.display());

    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create parent directory: {}", parent.display()))
            .map_err(StoreError::Io)?;
    }
    let error_file = file.with_added_extension("errors");
    fs::write(&error_file, document.data)
        .await
        .with_context(|| format!("Failed to write advisory errors: {}", error_file.display()))
        .map_err(StoreError::Io)?;

    Ok(())
}

/// Stores the document and associated files (checksums, signature, xattrs, timestamps).
pub async fn store_document(file: &Path, document: Document<'_>) -> Result<(), StoreError> {
    log::debug!("Writing {}", file.display());

    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create parent directory: {}", parent.display()))
            .map_err(StoreError::Io)?;
    }

    fs::write(&file, document.data)
        .await
        .with_context(|| format!("Failed to write advisory: {}", file.display()))
        .map_err(StoreError::Io)?;

    if let Some(sha256) = &document.sha256 {
        let file = format!("{}.sha256", file.display());
        fs::write(&file, &sha256.expected)
            .await
            .with_context(|| format!("Failed to write checksum: {file}"))
            .map_err(StoreError::Io)?;
    }
    if let Some(sha512) = &document.sha512 {
        let file = format!("{}.sha512", file.display());
        fs::write(&file, &sha512.expected)
            .await
            .with_context(|| format!("Failed to write checksum: {file}"))
            .map_err(StoreError::Io)?;
    }
    if let Some(sig) = &document.signature {
        let file = format!("{}.asc", file.display());
        fs::write(&file, &sig)
            .await
            .with_context(|| format!("Failed to write signature: {file}"))
            .map_err(StoreError::Io)?;
    }

    if !document.no_timestamps {
        // We use the retrieval metadata timestamp as file timestamp. If that's not available, then
        // we use the change entry timestamp.
        let mtime = document
            .metadata
            .last_modification
            .map(SystemTime::from)
            .unwrap_or_else(|| document.changed)
            .into();
        filetime::set_file_mtime(file, mtime)
            .with_context(|| {
                format!(
                    "Failed to set last modification timestamp: {}",
                    file.display()
                )
            })
            .map_err(StoreError::Io)?;
    }

    if !document.no_xattrs
        && let Some(etag) = &document.metadata.etag
    {
        fsquirrel::set(file, ATTR_ETAG, etag.as_bytes())
            .with_context(|| format!("Failed to store {}: {}", ATTR_ETAG, file.display()))
            .map_err(StoreError::Io)?;
    }

    Ok(())
}
