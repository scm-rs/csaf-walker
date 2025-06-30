mod render;

use crate::{cmd::DiscoverArguments, common::walk_visitor, inspect::inspect};
use parking_lot::Mutex;
use reqwest::Url;
use sbom_walker::{
    model::sbom::ParseAnyError,
    report::ReportResult,
    retrieve::RetrievingVisitor,
    source::{DispatchSource, Source},
    validation::{ValidatedSbom, ValidationVisitor},
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::task;
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    progress::Progress,
    report::{self, Statistics},
    utils::url::Urlify,
    validate::{ValidationError, ValidationOptions},
};

#[derive(Debug, thiserror::Error)]
pub enum SbomError<S: Source> {
    #[error(transparent)]
    Validation(#[from] ValidationError<S>),
    #[error(transparent)]
    Parse(#[from] ParseAnyError),
}

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
    validation: ValidationArguments,

    #[command(flatten)]
    render: RenderOptions,
}

impl CommandDefaults for Report {}

#[derive(clap::Args, Debug)]
pub struct RenderOptions {
    /// Path of the HTML output file
    #[arg(long, default_value = "report.html")]
    output: PathBuf,

    /// Make links relative to this URL.
    #[arg(short = 'B', long)]
    base_url: Option<Url>,

    /// Override source URL
    #[arg(long)]
    source_url: Option<Url>,

    /// Statistics file to append to
    #[arg(long)]
    statistics_file: Option<PathBuf>,
}

impl Report {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let total: Arc<AtomicUsize> = Default::default();
        let errors: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();

        {
            let total = total.clone();
            let errors = errors.clone();
            walk_visitor(
                progress,
                self.client,
                self.discover,
                self.runner,
                async |source| {
                    Ok(RetrievingVisitor::new(
                        source.clone(),
                        ValidationVisitor::new(
                            move |sbom: Result<ValidatedSbom, ValidationError<DispatchSource>>| {
                                let errors = errors.clone();
                                total.fetch_add(1, Ordering::SeqCst);
                                async move {
                                    let name = match &sbom {
                                        Ok(sbom) => sbom.url.to_string(),
                                        Err(sbom) => sbom.url().to_string(),
                                    };

                                    task::spawn_blocking(move || {
                                        inspect(&(name, errors), sbom);
                                    })
                                    .await
                                    .expect("unable to spawn inspection");

                                    Ok::<_, anyhow::Error>(())
                                }
                            },
                        )
                        .with_options(options),
                    ))
                },
            )
            .await?;
        }

        let total = total.load(Ordering::SeqCst);
        let errors = errors.lock();

        Self::render(
            &self.render,
            &ReportResult {
                errors: &errors,
                total,
            },
        )?;

        report::record_now(
            self.render.statistics_file.as_deref(),
            Statistics {
                total,
                errors: errors.len(),
                total_errors: errors.values().map(|v| v.len()).sum(),
                warnings: 0,
                total_warnings: 0,
            },
        )?;

        Ok(())
    }

    fn render(render: &RenderOptions, report: &ReportResult) -> anyhow::Result<()> {
        let mut out = std::fs::File::create(&render.output)?;
        render::render_to_html(&mut out, report, render)?;

        Ok(())
    }
}
