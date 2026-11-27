pub use crate::check::CheckError;

use crate::{check::Capped, verification::RawCsaf};
use async_trait::async_trait;
use csaf_rs::validation::{TestResultStatus, Validatable, ValidationError};
use parking_lot::Mutex;
use std::{cell::Cell, collections::HashMap, sync::Arc};

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
        let CheckError { id, message } = item;
        self.push_with(id, || message);
    }

    /// Counts an item, but only creates its message if the item is stored.
    ///
    /// This avoids allocating (or interning) messages which would be dropped by the cap.
    pub fn push_with(&mut self, id: Arc<str>, message: impl FnOnce() -> Arc<str>) {
        let (pushed, items) = self.items.entry(id.clone()).or_default();

        // Create the message before counting, so a panic doesn't leave a phantom omitted issue.
        if self.cap == 0 || items.len() < self.cap {
            let message = message();
            items.push(CheckError { id, message });
        }

        *pushed += 1;
        self.total += 1;
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

#[async_trait]
pub trait Check: Send + Sync {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &RawCsaf) -> anyhow::Result<CheckResult>;
}

/// Implementation to allow a simple function style check
#[async_trait]
impl<F> Check for F
where
    F: Fn(&RawCsaf) -> Vec<CheckError> + Send + Sync,
{
    async fn check(&self, csaf: &RawCsaf) -> anyhow::Result<CheckResult> {
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

/// Pool size below which the intern pool is never pruned.
const MIN_PRUNE_AT: usize = 4096;

/// A string intern pool which releases entries that are no longer in use.
///
/// Entries are kept while results still reference them, or when they were looked up again
/// since the last prune, so messages repeating across documents stay shared.
#[derive(Debug)]
struct InternPool {
    /// Interned strings, flagged when looked up again since the last prune.
    entries: HashMap<Arc<str>, Cell<bool>>,
    /// Pool size at which the next insert prunes unused entries first.
    prune_at: usize,
}

impl Default for InternPool {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            prune_at: MIN_PRUNE_AT,
        }
    }
}

impl InternPool {
    /// Returns the shared instance of `s`, adding it if needed.
    fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some((existing, hit)) = self.entries.get_key_value(s) {
            hit.set(true);
            return existing.clone();
        }

        if self.entries.len() >= self.prune_at {
            self.prune();
        }

        let arc: Arc<str> = Arc::from(s);
        self.entries.insert(arc.clone(), Cell::new(false));
        arc
    }

    /// Drops entries which are neither referenced elsewhere nor reused since the last prune.
    ///
    /// The threshold doubles with the remaining size, keeping pruning amortized constant per insert.
    fn prune(&mut self) {
        self.entries.retain(|s, hit| {
            // Always reset the flag, also for entries kept because they are still referenced.
            let reused = hit.take();
            Arc::strong_count(s) > 1 || reused
        });
        self.prune_at = MIN_PRUNE_AT.max(self.entries.len() * 2);
    }
}

pub struct CsafValidation {
    pub preset: String,
    pub max_issues_per_test: usize,
    interned: Mutex<InternPool>,
}

impl CsafValidation {
    pub fn new(preset: impl Into<String>) -> Self {
        Self {
            preset: preset.into(),
            max_issues_per_test: DEFAULT_MAX_ISSUES_PER_TEST,
            interned: Mutex::new(InternPool::default()),
        }
    }

    pub fn with_max_issues_per_test(mut self, max: usize) -> Self {
        self.max_issues_per_test = max;
        self
    }

    fn intern(&self, s: &str) -> Arc<str> {
        self.interned.lock().intern(s)
    }

    fn validate<V>(&self, csaf: &V) -> anyhow::Result<CheckResult>
    where
        V: Validatable,
    {
        fn collect(
            result: &mut Capping,
            errors: impl IntoIterator<Item = ValidationError>,
            id: &Arc<str>,
            intern: &dyn Fn(&str) -> Arc<str>,
        ) {
            for error in errors {
                result.push_with(Arc::clone(id), || intern(&error.message));
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

#[async_trait]
impl Check for CsafValidation {
    async fn check(&self, csaf: &RawCsaf) -> anyhow::Result<CheckResult> {
        match csaf {
            RawCsaf::V2_0(csaf) => self.validate(&**csaf),
            RawCsaf::V2_1(csaf) => self.validate(&**csaf),
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
    #[case::cap_zero(0, 2, 2, vec!["msg0", "msg1"])]
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

    /// Messages beyond the cap are counted, but never created.
    #[test]
    fn push_with_skips_capped_messages() {
        let mut capping = Capping::new(2);
        let mut created = 0;
        for i in 0..5 {
            capping.push_with(Arc::from("t"), || {
                created += 1;
                Arc::from(format!("msg{i}"))
            });
        }
        assert_eq!(created, 2);
        let capped = capping.finish();
        assert_eq!(capped.total, 5);
        assert_eq!(
            messages(&capped),
            ["msg0", "msg1", "threshold of 2 reached, 3 issues omitted"]
        );
    }

    /// Lookups share the same instance.
    #[test]
    fn intern_pool_shares_instances() {
        let mut pool = InternPool::default();
        let a = pool.intern("a");
        let b = pool.intern("a");
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// Pruning keeps referenced and reused entries, and drops the rest.
    #[test]
    fn intern_pool_prune_keeps_used_entries() {
        let mut pool = InternPool::default();
        let held = pool.intern("held");
        pool.intern("reused");
        pool.intern("reused");
        pool.intern("unused");

        pool.prune();
        let mut kept: Vec<_> = pool.entries.keys().map(|s| s.to_string()).collect();
        kept.sort();
        assert_eq!(kept, ["held", "reused"]);
        let (stored, _) = pool.entries.get_key_value("held").unwrap();
        assert!(Arc::ptr_eq(&held, stored));

        // The reuse flag is reset by a prune, so an idle entry goes at the next one.
        drop(held);
        pool.prune();
        assert!(pool.entries.is_empty());
    }

    /// A reuse flag set while an entry is still referenced doesn't outlive the next prune.
    #[test]
    fn intern_pool_prune_resets_flag_of_referenced_entries() {
        let mut pool = InternPool::default();
        let held = pool.intern("held");
        let again = pool.intern("held");
        drop(again);

        pool.prune();
        assert_eq!(pool.entries.len(), 1);

        drop(held);
        pool.prune();
        assert!(pool.entries.is_empty());
    }

    /// Reaching the threshold prunes before inserting, then doubles the threshold.
    #[test]
    fn intern_pool_prunes_at_threshold() {
        let mut pool = InternPool::default();
        let held: Vec<_> = (0..MIN_PRUNE_AT / 2)
            .map(|i| pool.intern(&format!("held{i}")))
            .collect();
        for i in 0..MIN_PRUNE_AT / 2 {
            pool.intern(&format!("unused{i}"));
        }
        assert_eq!(pool.entries.len(), MIN_PRUNE_AT);

        pool.intern("next");
        assert_eq!(pool.entries.len(), held.len() + 1);
        assert_eq!(pool.prune_at, MIN_PRUNE_AT);

        // Entries still referenced survive, so the threshold grows with them.
        let more: Vec<_> = (0..MIN_PRUNE_AT)
            .map(|i| pool.intern(&format!("more{i}")))
            .collect();
        assert_eq!(pool.entries.len(), held.len() + more.len());
        assert!(pool.prune_at > MIN_PRUNE_AT);
    }
}
