use crate::{
    cmd::{DiscoverArguments, FilterArguments, VerificationArguments},
    common::walk_visitor,
};
use csaf_walker::{
    discover::AsDiscovered,
    report::{
        DocumentKey, Duplicates, ReportRenderOption, ReportResult, get_client_error_status,
        render_to_html,
    },
    retrieve::RetrievingVisitor,
    source::DispatchSource,
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{
        VerificationError, VerifiedAdvisory, VerifyingVisitor,
        check::{CheckError, init_verifying_visitor},
    },
    visitors::duplicates::DetectDuplicatesVisitor,
};
use reqwest::{StatusCode, Url};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Mutex;
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, parser::parse_allow_client_errors,
        runner::RunnerArguments, validation::ValidationArguments,
    },
    progress::Progress,
    report::{self, Statistics},
    retrieve::RetrievalError,
    utils::url::Urlify,
    validate::ValidationOptions,
};

/// Analyze (and report) the state of the data.
#[derive(clap::Args, Debug)]
pub struct Report {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    verification: VerificationArguments,

    #[command(flatten)]
    render: RenderOptions,

    /// Shorthand for `--allow-client-errors 404`.
    #[arg(long)]
    allow_missing: bool,

    /// Classify retrieval failures with these 4xx status codes separately in the report.
    #[arg(long)]
    allow_client_errors: Vec<String>,
}

impl CommandDefaults for Report {}

#[derive(clap::Args, Debug)]
#[command(next_help_heading = "Report rendering")]
pub struct RenderOptions {
    /// Path of the HTML output file
    #[arg(long, default_value = "report.html")]
    pub output: PathBuf,

    /// Make links relative to this URL.
    #[arg(short = 'B', long)]
    pub base_url: Option<Url>,

    /// The original source URL, used for the summary.
    #[arg(long)]
    pub source_url: Option<Url>,

    /// Statistics file to append to
    #[arg(long)]
    statistics_file: Option<PathBuf>,
}

impl Report {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();
        let allowed_client_errors =
            parse_allow_client_errors(self.allow_missing, self.allow_client_errors)?;

        let total = Arc::new(AtomicUsize::default());
        let duplicates: Arc<Mutex<Duplicates>> = Default::default();
        let errors: Arc<Mutex<BTreeMap<DocumentKey, String>>> = Default::default();
        let warnings: Arc<Mutex<BTreeMap<DocumentKey, Vec<CheckError>>>> = Default::default();
        let ignored_errors: Arc<Mutex<BTreeMap<DocumentKey, StatusCode>>> = Default::default();

        {
            let total = total.clone();
            let duplicates = duplicates.clone();
            let errors = errors.clone();
            let warnings = warnings.clone();
            let ignored_errors = ignored_errors.clone();

            let visitor = move |advisory: Result<
                VerifiedAdvisory<ValidatedAdvisory, &'static str>,
                VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>,
            >| {
                (*total).fetch_add(1, Ordering::Release);

                let errors = errors.clone();
                let warnings = warnings.clone();
                let ignored_errors = ignored_errors.clone();
                let allowed_client_errors = allowed_client_errors.clone();

                async move {
                    let adv = match advisory {
                        Ok(adv) => adv,
                        Err(err) => {
                            let name = match err.as_discovered().relative_base_and_url() {
                                Some((base, relative)) => DocumentKey {
                                    distribution_url: base.clone(),
                                    url: relative,
                                },
                                None => DocumentKey {
                                    distribution_url: err.url().clone(),
                                    url: Default::default(),
                                },
                            };

                            if let Some(status) = get_client_error_status(&err)
                                && allowed_client_errors.contains(&status)
                            {
                                ignored_errors.lock().await.insert(name, status);
                                return Ok::<_, anyhow::Error>(());
                            }

                            errors.lock().await.insert(name, err.to_string());
                            return Ok::<_, anyhow::Error>(());
                        }
                    };

                    if !adv.failures.is_empty() {
                        let name = DocumentKey::for_document(&adv);
                        warnings
                            .lock()
                            .await
                            .entry(name)
                            .or_default()
                            .extend(adv.failures.into_values().flatten());
                    }

                    Ok::<_, anyhow::Error>(())
                }
            };

            // content checks

            let visitor = VerifyingVisitor::with_checks(visitor, init_verifying_visitor());

            // validation (can we work with this document?)

            let visitor = ValidationVisitor::new(visitor).with_options(options);

            walk_visitor(
                progress,
                self.client,
                self.discover,
                self.filter,
                self.runner,
                async move |source| {
                    let visitor = RetrievingVisitor::new(source.clone(), visitor);

                    Ok(DetectDuplicatesVisitor {
                        duplicates,
                        visitor,
                    })
                },
            )
            .await?;
        }

        let total = (*total).load(Ordering::Acquire);
        let errors = errors.lock().await;
        let warnings = warnings.lock().await;
        let ignored_errors = ignored_errors.lock().await;

        Self::render(
            &self.render,
            &ReportResult {
                total,
                duplicates: &*duplicates.lock().await,
                errors: &errors,
                warnings: &warnings,
                ignored_errors: &ignored_errors,
            },
        )?;

        report::record_now(
            self.render.statistics_file.as_deref(),
            Statistics {
                total,
                errors: errors.len(),
                total_errors: errors.len(),
                warnings: warnings.len(),
                total_warnings: warnings.values().map(|v| v.len()).sum(),
            },
        )?;

        Ok(())
    }

    fn render(render: &RenderOptions, report: &ReportResult) -> anyhow::Result<()> {
        let mut out = std::fs::File::create(&render.output)?;

        render_to_html(
            &mut out,
            report,
            ReportRenderOption {
                output: &render.output,
                base_url: &render.base_url,
                source_url: &render.source_url,
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csaf_walker::discover::DistributionContext;
    use csaf_walker::source::{DispatchSourceError, HttpSourceError};
    use csaf_walker::{discover::DiscoveredAdvisory, retrieve::RetrievedAdvisory};
    use rstest::rstest;
    use std::sync::Arc;
    use walker_common::{fetcher, retrieve::RetrievalMetadata};

    fn test_discovered() -> DiscoveredAdvisory {
        DiscoveredAdvisory {
            context: Arc::new(DistributionContext::Directory(
                Url::parse("https://example.com/advisories/").unwrap(),
            )),
            url: Url::parse("https://example.com/advisories/test.json").unwrap(),
            digest: None,
            signature: None,
            modified: std::time::SystemTime::now(),
        }
    }

    fn test_retrieved() -> RetrievedAdvisory {
        RetrievedAdvisory {
            discovered: test_discovered(),
            data: bytes::Bytes::from_static(b"{}"),
            signature: None,
            sha256: None,
            sha512: None,
            metadata: RetrievalMetadata {
                last_modification: None,
                etag: None,
            },
        }
    }

    fn make_client_error(
        status: StatusCode,
    ) -> VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory> {
        VerificationError::Upstream(ValidationError::Retrieval(RetrievalError::Source {
            discovered: test_discovered(),
            err: DispatchSourceError::Http(HttpSourceError::Fetcher(fetcher::Error::ClientError(
                status,
            ))),
        }))
    }

    #[rstest]
    #[case::not_found(StatusCode::NOT_FOUND)]
    #[case::forbidden(StatusCode::FORBIDDEN)]
    fn extract_client_error(#[case] status: StatusCode) {
        let err = make_client_error(status);
        assert_eq!(get_client_error_status(&err), Some(status));
    }

    fn parsing_error() -> VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory> {
        VerificationError::Parsing {
            advisory: ValidatedAdvisory {
                retrieved: test_retrieved(),
            },
            error: serde_json::from_str::<String>("invalid").unwrap_err(),
        }
    }

    fn digest_mismatch_error()
    -> VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory> {
        VerificationError::Upstream(ValidationError::DigestMismatch {
            expected: "abc".to_string(),
            actual: "def".to_string(),
            retrieved: test_retrieved(),
        })
    }

    fn file_source_error() -> VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>
    {
        VerificationError::Upstream(ValidationError::Retrieval(RetrievalError::Source {
            discovered: test_discovered(),
            err: DispatchSourceError::File(anyhow::anyhow!("file not found")),
        }))
    }

    fn rate_limited_error() -> VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>
    {
        VerificationError::Upstream(ValidationError::Retrieval(RetrievalError::Source {
            discovered: test_discovered(),
            err: DispatchSourceError::Http(HttpSourceError::Fetcher(fetcher::Error::RateLimited(
                std::time::Duration::from_secs(60),
            ))),
        }))
    }

    #[rstest]
    #[case::parsing_error(parsing_error())]
    #[case::digest_mismatch(digest_mismatch_error())]
    #[case::file_source_error(file_source_error())]
    #[case::rate_limited(rate_limited_error())]
    fn returns_none_for_non_client_errors(
        #[case] err: VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>,
    ) {
        assert_eq!(get_client_error_status(&err), None);
    }
}
