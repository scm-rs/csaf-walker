pub use crate::check::CheckError;

use crate::verification::Csaf;
use async_trait::async_trait;
use csaf::validation::{TestResultStatus, Validatable, ValidationError};
use parking_lot::Mutex;
use std::{collections::HashSet, sync::Arc};

pub struct CheckResult {
    pub errors: Vec<CheckError>,
    pub total: usize,
}

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<CheckResult>;
}

/// Implementation to allow a simple function style check
#[async_trait(?Send)]
impl<F> Check for F
where
    F: Fn(&Csaf) -> Vec<CheckError>,
{
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<CheckResult> {
        let errors = (self)(csaf);
        let total = errors.len();
        Ok(CheckResult { errors, total })
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
        let mut pool = self.interned.lock();
        if let Some(existing) = pool.get(s) {
            existing.clone()
        } else {
            let arc: Arc<str> = Arc::from(s);
            pool.insert(arc.clone());
            arc
        }
    }

    fn validate<V>(&self, csaf: &V) -> anyhow::Result<CheckResult>
    where
        V: Validatable,
    {
        fn collect(
            result: &mut Vec<CheckError>,
            errors: Vec<ValidationError>,
            remaining: &mut usize,
            id: &Arc<str>,
            intern: &dyn Fn(&str) -> Arc<str>,
        ) {
            for error in errors {
                if *remaining == 0 {
                    return;
                }
                *remaining -= 1;
                result.push(CheckError {
                    id: Arc::clone(id),
                    message: intern(&error.message),
                });
            }
        }

        let tests = V::tests_in_preset(self.preset);
        let cap = self.max_issues_per_test;
        let mut results = vec![];
        let mut grand_total = 0usize;

        for test in tests.into_iter().flatten() {
            let result = csaf.run_test(test);

            if let TestResultStatus::Failure {
                errors,
                warnings,
                infos,
            } = result.status
            {
                let total = errors.len() + warnings.len() + infos.len();
                grand_total += total;
                let mut remaining = if cap == 0 { usize::MAX } else { cap };
                let intern = |s: &str| self.intern(s);
                let id = self.intern(test);

                collect(&mut results, errors, &mut remaining, &id, &intern);
                collect(&mut results, warnings, &mut remaining, &id, &intern);
                collect(&mut results, infos, &mut remaining, &id, &intern);

                if cap > 0 && total > cap {
                    results.push(CheckError {
                        id: Arc::clone(&id),
                        message: self.intern(&format!(
                            "threshold of {cap} reached, {} issues omitted",
                            total - cap,
                        )),
                    });
                }
            }
        }

        Ok(CheckResult {
            errors: results,
            total: grand_total,
        })
    }
}

#[async_trait(?Send)]
impl Check for CsafValidation {
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<CheckResult> {
        match csaf {
            Csaf::V2_0(csaf) => self.validate(csaf),
            Csaf::V2_1(csaf) => self.validate(csaf),
        }
    }
}
