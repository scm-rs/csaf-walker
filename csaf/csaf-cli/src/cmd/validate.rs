use csaf_walker::verification::{
    Csaf,
    check::{Check, CsafValidation, DEFAULT_MAX_ISSUES_PER_TEST},
};
use std::path::PathBuf;
use walker_common::{cli::CommandDefaults, locale::Formatted, progress::Progress};

/// Validate a CSAF document
#[derive(clap::Args, Debug)]
pub struct Validate {
    /// File to validate
    file: PathBuf,

    /// Validation preset
    #[arg(long, default_value = "full")]
    preset: String,

    /// Maximum number of issues reported per validation test. Use 0 for unlimited.
    #[arg(long, default_value_t = DEFAULT_MAX_ISSUES_PER_TEST)]
    max_issues_per_test: usize,
}

impl CommandDefaults for Validate {}

impl Validate {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        progress.start(1);

        let data = std::fs::read(&self.file)?;
        let csaf = Csaf::parse(&*data)?;

        let check =
            CsafValidation::new(&self.preset).with_max_issues_per_test(self.max_issues_per_test);
        let result = check.check(&csaf).await?;

        let filename = self.file.display();
        let total = result.total_errors + result.total_warnings + result.total_infos;

        println!("# Validation: {filename}\n");
        println!("**Preset:** {}  ", self.preset);

        if total == 0 {
            println!("\nNo issues found.");
        } else {
            println!(
                "**Issues:** {} error(s), {} warning(s), {} info(s)\n",
                Formatted(result.total_errors),
                Formatted(result.total_warnings),
                Formatted(result.total_infos),
            );
            for error in &result.errors {
                println!("- ERROR [{}] {}", error.id, error.message);
            }
            for warning in &result.warnings {
                println!("- WARN  [{}] {}", warning.id, warning.message);
            }
            for info in &result.infos {
                println!("- INFO  [{}] {}", info.id, info.message);
            }
        }

        Ok(())
    }
}
