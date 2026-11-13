//! Validation through [`Csaf`] must produce the same results as using csaf-rs directly.

#![cfg(feature = "csaf")]

use csaf_rs::{
    csaf::raw::RawDocument,
    csaf2_0::loader::load_document,
    schema::csaf2_0::schema::CommonSecurityAdvisoryFramework,
    validation::{TestResultStatus, Validatable, ValidationError, validate_by_preset},
};
use csaf_walker::{
    check::Capped,
    verification::{
        Csaf,
        check::{Check, CsafValidation},
    },
};
use rstest::rstest;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// A single finding: severity, test ID, message.
type Finding = (&'static str, String, String);

fn fixture(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(file)
}

/// Findings of csaf-rs, validating its own [`RawDocument`].
fn reference(
    document: &RawDocument<CommonSecurityAdvisoryFramework>,
    preset: &str,
) -> Vec<Finding> {
    let result = validate_by_preset(document, "2.0", preset).unwrap();

    let mut findings = Vec::new();
    for test in result.test_results {
        if let TestResultStatus::Failure {
            errors,
            warnings,
            infos,
        } = test.status
        {
            for (severity, items) in [("error", errors), ("warning", warnings), ("info", infos)] {
                findings.extend(items.into_iter().map(|ValidationError { message, .. }| {
                    (severity, test.test_id.clone(), message)
                }));
            }
        }
    }
    findings.sort();
    findings
}

/// Findings of csaf-walker, validating a [`Csaf`].
async fn walker(csaf: &Csaf, preset: &str) -> Vec<Finding> {
    // a cap of zero disables capping
    let result = CsafValidation::new(preset)
        .with_max_issues_per_test(0)
        .check(csaf)
        .await
        .unwrap();

    let mut findings = Vec::new();
    for (severity, capped) in [
        ("error", result.errors),
        ("warning", result.warnings),
        ("info", result.infos),
    ] {
        let Capped { items, total } = capped;
        assert_eq!(items.len(), total, "must not be capped");
        findings.extend(
            items
                .into_iter()
                .map(|error| (severity, error.id.to_string(), error.message.to_string())),
        );
    }
    findings.sort();
    findings
}

/// Validating through [`Csaf`] must give the same results as csaf-rs' own [`RawDocument`].
///
/// This compares the result of every single test, including passing and skipped ones, so tests
/// which silently don't run are caught. It also compares the findings of [`CsafValidation`] for
/// every preset, which covers how walker collects the results.
///
/// `translator.json` is `good.json` with a translator as publisher, but without `source_lang`. It
/// fails test 6.1.15, which csaf-rs only runs on the raw JSON.
///
/// `rhba-2023_0564.json` is not part of this, as it doesn't deserialize and so can't be parsed
/// into a [`Csaf`].
#[rstest]
#[case::rhsa_2021_3029("test-data/rhsa-2021_3029.json")] // valid schema, fails 6.1.1 (missing product ID definition) once
#[case::rhsa_2023_3408("test-data/rhsa-2023_3408.json")] // fails the raw-only schema test once, and 6.1.27.11
#[case::rhsa_2023_1441("test-data/rhsa-2023_1441.json")] // fails the raw-only schema test three times, warns on the raw-only 6.2.13
#[case::rhsa_2023_4378("test-data/rhsa-2023_4378.json")] // valid schema, fails 6.1.1 (missing product ID definition) 16 times
#[case::good("test-data/good.json")] // passes all mandatory tests, only warnings and infos
#[case::translator("test-data/translator.json")] // fails the raw-only 6.1.15 (translator without source_lang) once
#[tokio::test]
async fn same_results_as_csaf_rs(#[case] file: &str) {
    let path = fixture(file);
    // csaf-rs' own loader, creating a `RawDocument`
    let reference_document: RawDocument<CommonSecurityAdvisoryFramework> =
        load_document(&path).unwrap();
    let csaf = Csaf::parse(&path).unwrap();
    let Csaf::V2_0(document) = &csaf else {
        panic!("{file}: expected a CSAF 2.0 document");
    };

    let mut tests: BTreeSet<&str> = CommonSecurityAdvisoryFramework::get_tests()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    for preset in CommonSecurityAdvisoryFramework::get_presets() {
        tests.extend(CommonSecurityAdvisoryFramework::tests_in_preset(preset).unwrap());
    }

    let mut run = 0;
    for test in tests {
        let expected = reference_document.run_test(test).status;
        if expected != TestResultStatus::NotFound {
            run += 1;
        }
        assert_eq!(document.run_test(test).status, expected, "{file} / {test}");
    }
    assert!(run > 0, "{file}: no tests run");

    for preset in CommonSecurityAdvisoryFramework::get_presets() {
        assert_eq!(
            walker(&csaf, preset).await,
            reference(&reference_document, preset),
            "{file} / {preset}"
        );
    }
}
