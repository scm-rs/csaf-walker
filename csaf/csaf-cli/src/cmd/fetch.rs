use crate::{
    cmd::{DiscoverArguments, FilterArguments, SkipArguments},
    common::walk_visitor,
};
use colored_json::write_colored_json;
use csaf_walker::{
    discover::DiscoverConfig, retrieve::RetrievingVisitor, validation::ValidatedAdvisory,
    validation::ValidationVisitor,
};
use jsonpath_rust::JsonPath;
use serde_json::Value;
use std::io::Write;
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    progress::Progress,
    since::Since,
    validate::ValidationOptions,
};

/// Discover, retrieve, validate, and print documents.
#[derive(clap::Args, Debug)]
pub struct Fetch {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    skip: SkipArguments,

    /// The output format
    #[arg(short, long, default_value = "json")]
    output: String,

    /// Enable pretty printing for the output
    #[arg(short, long)]
    pretty: bool,
}

impl CommandDefaults for Fetch {
    fn progress(&self) -> bool {
        false
    }
}

fn write(pretty: bool, value: &Value) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    if pretty {
        let _ = write_colored_json(value, &mut out);
    } else {
        let _ = serde_json::to_writer(&mut out, value);
    }

    writeln!(&mut out)?;

    Ok(())
}

fn show(output: &str, pretty: bool, doc: ValidatedAdvisory) -> anyhow::Result<()> {
    let doc: Value = serde_json::from_slice(&doc.data)?;

    if output == "json" {
        write(pretty, &doc)?;
    } else if let Some(path) = output.strip_prefix("jsonpath=") {
        let result = doc.query(path)?;
        write(pretty, &serde_json::to_value(&result)?)?;
    } else {
        eprintln!("Unrecognized output format: {output}");
    }

    Ok(())
}

impl Fetch {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let since = Since::new(
            self.skip.since,
            self.skip.since_file,
            self.skip
                .since_file_offset
                .map(|d| d.into())
                .unwrap_or_default(),
        )?;

        let show = async |doc| {
            show(&self.output, self.pretty, doc?)?;

            Ok::<_, anyhow::Error>(())
        };

        walk_visitor(
            progress,
            self.client,
            DiscoverConfig::from(self.discover).with_since(since.since),
            self.filter,
            self.runner,
            async |source| {
                let validation = ValidationVisitor::new(show).with_options(options);
                Ok(RetrievingVisitor::new(source.clone(), validation))
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
