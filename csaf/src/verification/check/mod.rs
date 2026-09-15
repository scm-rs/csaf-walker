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
    /// Per-ID push count and stored items
    items: HashMap<Arc<str>, (usize, Vec<CheckError>)>,
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

        for (id, (pushed, mut items)) in self.items {
            let omitted = pushed - items.len();
            if omitted > 0 {
                items.push(CheckError {
                    id: id.clone(),
                    message: Arc::from(format!(
                        "threshold of {cap} reached, {omitted} issues omitted",
                        cap = self.cap,
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
        self.total += 1;

        let (pushed, items) = self.items.entry(item.id.clone()).or_default();
        *pushed += 1;

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

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    fn err(id: &str, msg: &str) -> CheckError {
        CheckError {
            id: Arc::from(id),
            message: Arc::from(msg),
        }
    }

    fn messages(capped: &Capped) -> Vec<String> {
        capped.items.iter().map(|e| e.message.to_string()).collect()
    }

    // --- Capping: single-ID parameterized tests ---

    #[rstest]
    #[case::empty(5, 0, 0, vec![])]
    #[case::under_cap(5, 2, 2, vec!["msg0", "msg1"])]
    #[case::at_cap(3, 3, 3, vec!["msg0", "msg1", "msg2"])]
    #[case::over_cap(3, 7, 7, vec!["msg0", "msg1", "msg2", "threshold of 3 reached, 4 issues omitted"])]
    #[case::cap_zero(0, 2, 2, vec!["threshold of 0 reached, 2 issues omitted"])]
    #[case::cap_one_over(1, 2, 2, vec!["msg0", "threshold of 1 reached, 1 issues omitted"])]
    #[case::cap_one_exact(1, 1, 1, vec!["msg0"])]
    fn capping_single_id(
        #[case] cap: usize,
        #[case] pushes: usize,
        #[case] expected_total: usize,
        #[case] expected_messages: Vec<&str>,
    ) {
        let mut c = Capping::new(cap);
        for i in 0..pushes {
            c.push(err("A", &format!("msg{i}")));
        }

        let result = c.finish();
        assert_eq!(result.total, expected_total);
        assert_eq!(messages(&result), expected_messages);
    }

    // --- Capping: multi-ID and extend ---

    #[test]
    fn capping_per_id_isolation() {
        let mut c = Capping::new(2);
        c.push(err("A", "a1"));
        c.push(err("A", "a2"));
        c.push(err("A", "a3")); // over cap for A
        c.push(err("B", "b1")); // under cap for B

        let result = c.finish();
        assert_eq!(result.total, 4);

        let a_msgs: Vec<_> = result
            .items
            .iter()
            .filter(|e| &*e.id == "A")
            .map(|e| e.message.to_string())
            .collect();
        assert_eq!(
            a_msgs,
            vec!["a1", "a2", "threshold of 2 reached, 1 issues omitted"]
        );

        let b_msgs: Vec<_> = result
            .items
            .iter()
            .filter(|e| &*e.id == "B")
            .map(|e| e.message.to_string())
            .collect();
        assert_eq!(b_msgs, vec!["b1"]);
    }

    #[test]
    fn capping_extend() {
        let mut c = Capping::new(2);
        let items = vec![err("A", "e1"), err("A", "e2"), err("A", "e3")];
        (&mut c).extend(items);

        let result = c.finish();
        assert_eq!(result.total, 3);
        assert_eq!(
            messages(&result),
            vec!["e1", "e2", "threshold of 2 reached, 1 issues omitted"]
        );
    }

    #[test]
    fn capping_total_is_uncapped() {
        let mut c = Capping::new(3);
        for i in 0..10 {
            c.push(err("A", &format!("msg{i}")));
        }
        let result = c.finish();
        assert_eq!(result.total, 10);
        assert_eq!(result.items.len(), 4); // 3 stored + 1 threshold message
    }

    // --- CheckResult tests ---

    #[test]
    fn check_result_default_is_ok() {
        let r = CheckResult::default();
        assert!(r.is_ok());
        assert_eq!(r.total(), 0);
    }

    #[rstest]
    #[case::errors(
        CheckResult { errors: vec![err("A", "e")].into_iter().collect(), ..Default::default() }
    )]
    #[case::warnings(
        CheckResult { warnings: vec![err("A", "w")].into_iter().collect(), ..Default::default() }
    )]
    #[case::infos(
        CheckResult { infos: vec![err("A", "i")].into_iter().collect(), ..Default::default() }
    )]
    fn check_result_is_not_ok(#[case] r: CheckResult) {
        assert!(!r.is_ok());
    }

    #[test]
    fn check_result_total_reflects_uncapped_counts() {
        let r = CheckResult {
            errors: Capped {
                items: vec![err("A", "e1")],
                total: 50,
            },
            warnings: Capped {
                items: vec![],
                total: 30,
            },
            infos: Capped {
                items: vec![err("A", "i1"), err("A", "i2")],
                total: 20,
            },
        };
        // total() sums Capped.total, not items.len()
        assert_eq!(r.total(), 100);
        assert_eq!(r.errors.items.len(), 1);
        assert_eq!(r.warnings.items.len(), 0);
        assert_eq!(r.infos.items.len(), 2);
    }

    // --- CsafValidation config tests ---

    #[test]
    fn default_max_issues() {
        assert_eq!(DEFAULT_MAX_ISSUES_PER_TEST, 25);
        let v = CsafValidation::new("optional");
        assert_eq!(v.max_issues_per_test, 25);
    }

    #[test]
    fn custom_max_issues() {
        let v = CsafValidation::new("optional").with_max_issues_per_test(100);
        assert_eq!(v.max_issues_per_test, 100);
    }
}
