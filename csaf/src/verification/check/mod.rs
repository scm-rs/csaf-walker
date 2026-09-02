use crate::verification::Csaf;
use async_trait::async_trait;
use csaf::validation::{TestResultStatus, Validatable, ValidationError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

mod arc_str_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub fn serialize<S: Serializer>(value: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Arc<str>, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Arc::from(s.as_str()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckError {
    #[serde(with = "arc_str_serde")]
    pub message: Arc<str>,
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

impl From<&str> for CheckError {
    fn from(s: &str) -> Self {
        CheckError {
            message: Arc::from(s),
        }
    }
}

impl From<String> for CheckError {
    fn from(s: String) -> Self {
        CheckError {
            message: Arc::from(s.as_str()),
        }
    }
}

pub const DEFAULT_MAX_ISSUES_PER_TEST: usize = 25;

pub struct CsafValidation {
    pub preset: &'static str,
    pub max_issues_per_test: usize,
    interned: Mutex<HashSet<Arc<str>>>,
}

impl CsafValidation {
    pub fn new(preset: &'static str) -> Self {
        Self {
            preset,
            max_issues_per_test: DEFAULT_MAX_ISSUES_PER_TEST,
            interned: Mutex::new(HashSet::new()),
        }
    }

    pub fn with_max_issues_per_test(mut self, max: usize) -> Self {
        self.max_issues_per_test = max;
        self
    }

    fn intern(&self, s: &str) -> Arc<str> {
        let mut pool = self.interned.lock().unwrap();
        if let Some(existing) = pool.get(s) {
            existing.clone()
        } else {
            let arc: Arc<str> = Arc::from(s);
            pool.insert(arc.clone());
            arc
        }
    }

    fn validate<V>(&self, csaf: &V) -> anyhow::Result<Vec<CheckError>>
    where
        V: Validatable,
    {
        fn collect(
            result: &mut Vec<CheckError>,
            errors: Vec<ValidationError>,
            remaining: &mut usize,
            intern: &dyn Fn(&str) -> Arc<str>,
        ) {
            for error in errors {
                if *remaining == 0 {
                    return;
                }
                *remaining -= 1;
                result.push(CheckError {
                    message: intern(&error.message),
                });
            }
        }

        let tests = V::tests_in_preset(self.preset);
        let cap = self.max_issues_per_test;
        let mut results = vec![];

        for test in tests.into_iter().flatten() {
            let result = csaf.run_test(test);

            if let TestResultStatus::Failure {
                errors,
                warnings,
                infos,
            } = result.status
            {
                let total = errors.len() + warnings.len() + infos.len();
                let mut remaining = if cap == 0 { usize::MAX } else { cap };
                let intern = |s: &str| self.intern(s);

                collect(&mut results, errors, &mut remaining, &intern);
                collect(&mut results, warnings, &mut remaining, &intern);
                collect(&mut results, infos, &mut remaining, &intern);

                if cap > 0 && total > cap {
                    results.push(CheckError {
                        message: self.intern(&format!(
                            "Test {test}: threshold of {cap} reached, {} issues omitted",
                            total - cap,
                        )),
                    });
                }
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
