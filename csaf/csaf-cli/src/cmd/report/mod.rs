use crate::{
    cmd::{DiscoverArguments, FilterArguments, VerificationArguments},
    common::walk_visitor,
};
use csaf_walker::{
    discover::AsDiscovered,
    report::{
        DocumentKey, Duplicates, FileBackedCollector, InMemoryCollector, ReportCollector,
        ReportRenderOption, ReportResult, ReportSeverity, ReportView, render_to_html,
    },
    retrieve::RetrievingVisitor,
    source::DispatchSource,
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{
        VerificationError, VerifiedAdvisory, VerifyingVisitor,
        check::{CheckError, CsafValidation},
    },
    visitors::duplicates::DetectDuplicatesVisitor,
};
use reqwest::Url;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Mutex;
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    progress::Progress,
    report::{self, Statistics},
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
}

impl CommandDefaults for Report {}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ReportStorageMode {
    /// Keep report data in memory (fast, higher memory usage)
    Memory,
    /// Spill report data to a temp file (lower memory during walk, slower)
    File,
}

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

    /// Storage mode for report data during collection.
    #[arg(long, default_value = "memory")]
    pub report_storage: ReportStorageMode,
}

impl Report {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        match self.render.report_storage {
            ReportStorageMode::Memory => {
                self.run_with_collector(progress, InMemoryCollector::new())
                    .await
            }
            ReportStorageMode::File => {
                self.run_with_collector(progress, FileBackedCollector::new()?)
                    .await
            }
        }
    }

    async fn run_with_collector<P, C>(self, progress: P, collector: C) -> anyhow::Result<()>
    where
        P: Progress,
        C: ReportCollector + 'static,
    {
        let options: ValidationOptions = self.validation.into();

        let total = Arc::new(AtomicUsize::default());
        let duplicates: Arc<Mutex<Duplicates>> = Default::default();
        let collector: Arc<Mutex<C>> = Arc::new(Mutex::new(collector));

        {
            let total = total.clone();
            let duplicates = duplicates.clone();
            let collector = collector.clone();

            let visitor = move |advisory: Result<
                VerifiedAdvisory<ValidatedAdvisory, &'static str>,
                VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>,
            >| {
                (*total).fetch_add(1, Ordering::Release);

                let collector = collector.clone();

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

                            collector.lock().await.insert(
                                name,
                                ReportSeverity::Error,
                                vec![CheckError::from(err.to_string())],
                            )?;
                            return Ok::<_, anyhow::Error>(());
                        }
                    };

                    if !adv.failures.is_empty() {
                        let name = DocumentKey::for_document(&adv);
                        let checks: Vec<CheckError> =
                            adv.failures.into_values().flatten().collect();
                        collector
                            .lock()
                            .await
                            .insert(name, ReportSeverity::Warning, checks)?;
                    }

                    Ok::<_, anyhow::Error>(())
                }
            };

            // content checks

            let check = CsafValidation::new("full")
                .with_max_issues_per_test(self.verification.max_issues_per_test);
            let visitor = VerifyingVisitor::with_checks(visitor, vec![("csaf", Box::new(check))]);

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

        let collector = Arc::try_unwrap(collector)
            .map_err(|_| anyhow::anyhow!("collector still has outstanding references"))?
            .into_inner();
        let view = collector.into_view()?;

        Self::render_report(
            &self.render,
            &ReportResult {
                total,
                duplicates: &*duplicates.lock().await,
                view: &view,
            },
        )?;

        report::record_now(
            self.render.statistics_file.as_deref(),
            Statistics {
                total,
                errors: view.count(&ReportSeverity::Error),
                total_errors: view.total(&ReportSeverity::Error),
                warnings: view.count(&ReportSeverity::Warning),
                total_warnings: view.total(&ReportSeverity::Warning),
            },
        )?;

        Ok(())
    }

    fn render_report(render: &RenderOptions, report: &ReportResult) -> anyhow::Result<()> {
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
