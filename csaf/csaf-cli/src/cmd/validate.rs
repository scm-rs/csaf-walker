use csaf_walker::verification::{
    Csaf,
    check::{CsafValidation, Check, DEFAULT_MAX_ISSUES_PER_TEST},
};
use std::path::PathBuf;
use walker_common::{cli::CommandDefaults, progress::Progress};

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
        let check = CsafValidation::new(preset)
            .with_max_issues_per_test(self.max_issues_per_test);
        let errors = check.check(&csaf).await?;

        let filename = self.file.display();

        if errors.is_empty() {
            println!("# Validation: {filename}\n");
            println!("**Preset:** {preset}\n");
            println!("No issues found.");
        } else {
            println!("# Validation: {filename}\n");
            println!("**Preset:** {preset}  ");
            println!("**Issues:** {}\n", errors.len());
            for error in &errors {
                println!("- {}", error.message);
            }
        }

        Ok(())
    }
}
