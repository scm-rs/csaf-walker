//! Parsed CSAF documents which keep their raw JSON for validation.

use csaf_rs::{
    csaf::raw::{RawDocument, RawValidatable},
    validation::{CsafError, TestResult, TestResultStatus, Validatable},
};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde_json::{Error as JsonError, Value};
use std::ops::Deref;

/// A successfully deserialized CSAF document, together with its raw JSON.
///
/// Some csaf-rs tests (like the schema validation) only run on the raw JSON of a
/// [`RawDocument`]. Unlike [`RawDocument`], this type is [`Sync`] and gives infallible
/// access to the parsed document, as deserialization is checked on construction.
#[derive(Debug)]
pub struct Document<T> {
    /// Raw JSON, only used for running raw tests.
    ///
    /// The raw tests only read the JSON, so its lazily parsed copy stays empty. The mutex
    /// is required because [`RawDocument`] is not [`Sync`].
    raw: Mutex<RawDocument<T>>,
    /// The deserialized document.
    parsed: T,
}

impl<T> Document<T>
where
    T: DeserializeOwned,
{
    /// Deserializes the document from its raw JSON.
    pub fn new(raw: Value) -> Result<Self, JsonError> {
        let parsed = T::deserialize(&raw)?;
        Ok(Self {
            raw: Mutex::new(RawDocument::new(raw)),
            parsed,
        })
    }
}

impl<T> Document<T> {
    /// The deserialized document.
    pub fn parsed(&self) -> &T {
        &self.parsed
    }
}

impl<T> Deref for Document<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.parsed
    }
}

impl<T> Clone for Document<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            raw: Mutex::new(self.raw.lock().clone()),
            parsed: self.parsed.clone(),
        }
    }
}

/// Mirrors the csaf-rs implementation for [`RawDocument`]: raw tests take precedence, all
/// other tests run on the parsed document.
impl<T> Validatable for Document<T>
where
    T: Validatable,
    RawDocument<T>: RawValidatable,
{
    fn get_presets() -> Vec<&'static str> {
        T::get_presets()
    }

    fn tests_in_preset(preset: &str) -> Result<Vec<&'static str>, CsafError> {
        T::tests_in_preset(preset)
    }

    fn get_tests() -> Vec<(&'static str, &'static str)> {
        T::get_tests()
    }

    fn has_test(test_id: &str) -> bool {
        T::has_test(test_id)
    }

    fn run_test(&self, test_id: &str) -> TestResult {
        let result = self.raw.lock().run_raw_test(test_id);
        if result.status != TestResultStatus::NotFound {
            return result;
        }
        self.parsed.run_test(test_id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use csaf_rs::schema::csaf2_0::schema::CommonSecurityAdvisoryFramework;

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync + Send>() {}
        assert_sync::<Document<CommonSecurityAdvisoryFramework>>();
    }
}
