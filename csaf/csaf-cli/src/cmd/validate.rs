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

        let preset: &'static str = Box::leak(self.preset.into_boxed_str());
        let check = CsafValidation::new(preset).with_max_issues_per_test(self.max_issues_per_test);
        let result = check.check(&csaf).await?;

        let filename = self.file.display();
        let shown = result.errors.len();
        let total = result.total;

        println!("# Validation: {filename}\n");
        println!("**Preset:** {preset}  ");

        if total == 0 {
            println!("\nNo issues found.");
        } else if shown == total {
            println!("**Issues:** {}\n", Formatted(total));
            for error in &result.errors {
                println!("- [{}] {}", error.id, error.message);
            }
        } else {
            println!(
                "**Issues:** {} ({} shown)\n",
                Formatted(total),
                Formatted(shown)
            );
            for error in &result.errors {
                println!("- [{}] {}", error.id, error.message);
            }
        }

        Ok(())
    }
}
