pub use crate::check::CheckError;

use crate::{check::Capped, verification::Csaf};
use async_trait::async_trait;
use csaf::validation::{TestResultStatus, Validatable, ValidationError};
use parking_lot::Mutex;
use std::{collections::HashMap, collections::HashSet, sync::Arc};

/// A `Vec` with capping support for `CheckError`.
#[derive(Clone)]
pub struct Capping {
    /// The maximum number of items
    cap: usize,
    /// The total number of entries (even when capped)
    total: usize,
    /// The actual content
    items: HashMap<Arc<str>, Vec<CheckError>>,
}

impl Capping {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            total: 0,
            items: Default::default(),
        }
    }

    pub fn finish(self) -> Capped {
        let mut result = Vec::new();

        for (id, mut items) in self.items {
            if items.len() == self.cap {
                items.push(CheckError {
                    id: id.clone(),
                    message: Arc::from(format!(
                        "threshold of {cap} reached, {omitted} issues omitted",
                        cap = self.cap,
                        omitted = self.total - self.cap,
                    )),
                })
            }

            result.extend(items);
        }

        Capped {
            total: self.total,
            items: result,
        }
    }

    pub fn push(&mut self, item: CheckError) {
        // always uptick
        self.total += 1;

        // now add it we have room
        let items = self.items.entry(item.id.clone()).or_default();

        if items.len() < self.cap {
            items.push(item);
        }
    }
}

impl Extend<CheckError> for &mut Capping {
    fn extend<T: IntoIterator<Item = CheckError>>(&mut self, iter: T) {
        for item in iter {
            self.push(item)
        }
    }
}

/// Result of running checks on a CSAF document.
#[derive(Clone, Default)]
pub struct CheckResult {
    /// Mandatory requirement violations.
    pub errors: Capped,
    /// Optional/recommended requirement violations.
    pub warnings: Capped,
    /// Informational notes.
    pub infos: Capped,
}

impl CheckResult {
    /// return `true` if all of the results are empty
    pub fn is_ok(&self) -> bool {
        self.errors.items.is_empty()
            && self.warnings.items.is_empty()
            && self.infos.items.is_empty()
    }

    /// return the totals for all severities summed up
    pub fn total(&self) -> usize {
        self.errors.total + self.warnings.total + self.infos.total
    }
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
        Ok(CheckResult {
            errors: Capped::from_iter(errors),
            ..Default::default()
        })
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
    pub preset: String,
    pub max_issues_per_test: usize,
    interned: Mutex<HashSet<Arc<str>>>,
}

impl CsafValidation {
    pub fn new(preset: impl Into<String>) -> Self {
        Self {
            preset: preset.into(),
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
            mut result: impl Extend<CheckError>,
            errors: impl IntoIterator<Item = ValidationError>,
            id: &Arc<str>,
            intern: &dyn Fn(&str) -> Arc<str>,
        ) {
            for error in errors {
                result.extend(Some(CheckError {
                    id: Arc::clone(id),
                    message: intern(&error.message),
                }));
            }
        }

        let tests = V::tests_in_preset(&self.preset);
        let mut errors = Capping::new(self.max_issues_per_test);
        let mut warnings = Capping::new(self.max_issues_per_test);
        let mut infos = Capping::new(self.max_issues_per_test);

        for test in tests.into_iter().flatten() {
            let result = csaf.run_test(test);

            if let TestResultStatus::Failure {
                errors: test_errors,
                warnings: test_warnings,
                infos: test_infos,
            } = result.status
            {
                let intern = |s: &str| self.intern(s);
                let id = self.intern(test);

                collect(&mut errors, test_errors, &id, &intern);
                collect(&mut warnings, test_warnings, &id, &intern);
                collect(&mut infos, test_infos, &id, &intern);
            }
        }

        Ok(CheckResult {
            errors: errors.finish(),
            warnings: warnings.finish(),
            infos: infos.finish(),
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
