use crate::{
    discover::DiscoveredAdvisory,
    model::{metadata::ProviderMetadata, store::distribution_base},
    retrieve::{RetrievalContext, RetrievedAdvisory, RetrievedVisitor},
    source::{HttpSourceError, Source},
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use anyhow::Context;
use sequoia_openpgp::{Cert, armor::Kind, serialize::SerializeInto};
use std::{
    any::Any,
    collections::HashSet,
    fmt::Debug,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    rc::Rc,
};
use tokio::fs;
use walker_common::{
    fetcher,
    retrieve::RetrievalError,
    store::{Document, ErrorData, StoreError, store_document, store_errors},
    utils::openpgp::PublicKey,
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

    /// the clients errors which can be ignored
    pub allowed_client_errors: HashSet<reqwest::StatusCode>,
}

impl StoreVisitor {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            no_timestamps: false,
            no_xattrs: false,
            allowed_client_errors: Default::default(),
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

    pub fn allow_client_errors(
        mut self,
        allowed_client_errors: HashSet<reqwest::StatusCode>,
    ) -> Self {
        self.allowed_client_errors = allowed_client_errors;
        self
    }

    /// Similar to [`Self::allow_client_errors`], but accepting any iterable and removing duplicates
    /// in the process.
    pub fn allow_client_errors_iter(
        self,
        allowed_client_errors: impl IntoIterator<Item = reqwest::StatusCode>,
    ) -> Self {
        self.allow_client_errors(allowed_client_errors.into_iter().collect())
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum StoreRetrievedError<S: Source> {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError<DiscoveredAdvisory, S>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum StoreValidatedError<S: Source> {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Validation(#[from] ValidationError<S>),
}

impl<S: Source + Debug> RetrievedVisitor<S> for StoreVisitor
where
    S::Error: 'static,
{
    type Error = StoreRetrievedError<S>;
    type Context = Rc<ProviderMetadata>;

    async fn visit_context(
        &self,
        context: &RetrievalContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.prepare_distributions(context.metadata).await?;
        self.store_keys(context.keys).await?;

        Ok(Rc::new(context.metadata.clone()))
    }

    /// Stores a retrieved advisory or its retrieval error.
    /// Fails if storing fails.
    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError<DiscoveredAdvisory, S>>,
    ) -> Result<(), Self::Error> {
        match result {
            Ok(advisory) => {
                self.store_advisory(&advisory).await?;
                Ok(())
            }
            Err(err) => {
                match Self::get_client_error_status_code(&err) {
                    Some(status) if self.allowed_client_errors.contains(&status) => {
                        self.store_error(status, err.discovered()).await?;
                    }
                    _ => return Err(StoreRetrievedError::Retrieval(err)),
                }
                Ok(())
            }
        }
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
        self.prepare_distributions(context.metadata).await?;
        self.store_keys(context.retrieval.keys).await?;
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        self.store_advisory(&result?.retrieved).await?;
        Ok(())
    }
}

impl StoreVisitor {
    async fn prepare_distributions(&self, metadata: &ProviderMetadata) -> Result<(), StoreError> {
        for dist in &metadata.distributions {
            if let Some(directory_url) = &dist.directory_url {
                let base = distribution_base(&self.base, directory_url.as_str());
                log::debug!("Creating base distribution directory: {}", base.display());

                fs::create_dir_all(&base)
                    .await
                    .with_context(|| {
                        format!(
                            "Unable to create distribution directory: {}",
                            base.display()
                        )
                    })
                    .map_err(StoreError::Io)?;
            }
            if let Some(rolie) = &dist.rolie {
                for feed in &rolie.feeds {
                    let base = distribution_base(&self.base, feed.url.as_str());
                    fs::create_dir_all(&base)
                        .await
                        .with_context(|| {
                            format!(
                                "Unable to create distribution directory: {}",
                                base.display()
                            )
                        })
                        .map_err(StoreError::Io)?;
                }
            }
        }

        Ok(())
    }

    async fn store_provider_metadata(&self, metadata: &ProviderMetadata) -> Result<(), StoreError> {
        let metadir = self.base.join(DIR_METADATA);

        fs::create_dir(&metadir)
            .await
            .or_else(|err| match err.kind() {
                ErrorKind::AlreadyExists => Ok(()),
                _ => Err(err),
            })
            .with_context(|| format!("Failed to create metadata directory: {}", metadir.display()))
            .map_err(StoreError::Io)?;

        let file = metadir.join("provider-metadata.json");
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
        std::fs::create_dir(&metadata)
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

    async fn store_advisory(&self, advisory: &RetrievedAdvisory) -> Result<(), StoreError> {
        log::info!(
            "Storing: {} (modified: {:?})",
            advisory.url,
            advisory.metadata.last_modification
        );

        let relative_url_result = advisory.context.url().make_relative(&advisory.url);
        let name = match &relative_url_result {
            Some(name) => name,
            None => return Err(StoreError::Filename(advisory.url.to_string())),
        };

        // create a distribution base
        let distribution_base = distribution_base(&self.base, advisory.context.url().as_str());

        // put the file there
        let file = distribution_base.join(name);

        store_document(
            &file,
            Document {
                data: &advisory.data,
                changed: advisory.modified,
                metadata: &advisory.metadata,
                sha256: &advisory.sha256,
                sha512: &advisory.sha512,
                signature: &advisory.signature,
                no_timestamps: self.no_timestamps,
                no_xattrs: self.no_xattrs,
            },
        )
        .await?;

        Ok(())
    }

    fn get_client_error_status_code<S: Source + Debug>(
        err: &RetrievalError<DiscoveredAdvisory, S>,
    ) -> Option<reqwest::StatusCode>
    where
        S::Error: 'static,
    {
        // Get the underlying source error by pattern matching
        let source_error = match err {
            RetrievalError::Source { err, .. } => err,
        };

        if let Some(http_error) = (source_error as &dyn Any).downcast_ref::<HttpSourceError>()
            && let HttpSourceError::Fetcher(fetcher::Error::ClientError(status)) = http_error
        {
            return Some(*status);
        }

        None
    }

    async fn store_error(
        &self,
        status_code: reqwest::StatusCode,
        discovered: &DiscoveredAdvisory,
    ) -> Result<(), StoreError> {
        log::warn!("Storing retrieval error for: {}", discovered.url);

        let relative_url_result = discovered.context.url().make_relative(&discovered.url);
        let name = match &relative_url_result {
            Some(name) => name,
            None => return Err(StoreError::Filename(discovered.url.to_string())),
        };

        let distribution_base = distribution_base(&self.base, discovered.context.url().as_str());
        let file = distribution_base.join(name);

        store_errors(
            &file,
            ErrorData {
                status_code: status_code.as_u16(),
            },
        )
        .await?;

        Ok(())
    }
}
