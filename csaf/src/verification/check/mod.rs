use crate::verification::Csaf;
use async_trait::async_trait;
use csaf::validation::{TestResultStatus, Validatable, ValidationError};
use std::borrow::Cow;

#[derive(Debug)]
pub struct CheckError {
    pub message: Cow<'static, str>,
}

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>>;
}

/// Implementation to allow a simple function style check
#[async_trait(?Send)]
impl<F> Check for F
where
    F: Fn(&Csaf) -> Vec<CheckError>,
{
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>> {
        Ok((self)(csaf))
    }
}

#[derive(Debug, Default)]
pub struct Checking {
    results: Vec<CheckError>,
}

impl Checking {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn require(mut self, msg: impl Into<CheckError>, ok: bool) -> Self {
        if !ok {
            self.results.push(msg.into());
        }
        self
    }

    pub fn done(self) -> Vec<CheckError> {
        self.results
    }
}

pub struct CsafValidation(pub &'static str);

impl CsafValidation {
    fn validate<V>(&self, csaf: &V) -> anyhow::Result<Vec<CheckError>>
    where
        V: Validatable,
    {
        fn add(result: &mut Vec<CheckError>, errors: Vec<ValidationError>) {
            for error in errors {
                result.push(CheckError {
                    message: error.message.into(),
                });
            }
        }

        let tests = V::tests_in_preset(self.0);

        let mut results = vec![];

        for test in tests.into_iter().flatten() {
            let result = csaf.run_test(test);

            if let TestResultStatus::Failure {
                errors,
                warnings,
                infos,
            } = result.status
            {
                add(&mut results, errors);
                add(&mut results, warnings);
                add(&mut results, infos);
            }
        }

        Ok(results)
    }
}

#[async_trait(?Send)]
impl Check for CsafValidation {
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>> {
        match csaf {
            Csaf::V2_0(csaf) => self.validate(csaf),
            Csaf::V2_1(csaf) => self.validate(csaf),
        }
    }
}
