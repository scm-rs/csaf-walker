use parking_lot::Mutex;
use sbom_walker::report;
use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "cyclonedx-bom")]
#[test]
fn test_cyclonedx_v13_json() {
    let _ = sbom_walker::Sbom::try_cyclonedx_json(include_bytes!("data/cyclonedx.v1_3.json"))
        .expect("must parse");
}

/// Ensure a CycloneDX 1.7 document is detected, and parsed as 1.7 (not as a previous version).
#[cfg(feature = "serde-cyclonedx")]
#[test]
fn test_cyclonedx_v17_json() {
    use sbom_walker::model::sbom::serde_cyclonedx;

    let sbom = sbom_walker::Sbom::try_parse_any(include_bytes!("data/cyclonedx.v1_7.json"))
        .expect("must parse");

    let sbom_walker::Sbom::SerdeCycloneDx(serde_cyclonedx::Sbom::V1_7(sbom)) = &sbom else {
        panic!("must be parsed as CycloneDX 1.7: {sbom:?}");
    };

    // `citations` was added in 1.7, so it would get dropped by any previous version
    assert_eq!(sbom.citations.iter().flatten().count(), 1);
}

#[cfg(any(feature = "cyclonedx-bom", feature = "serde-cyclonedx"))]
#[test]
fn cyclonedx_v17_inspect() {
    let sbom = sbom_walker::Sbom::try_parse_any(include_bytes!("data/cyclonedx.v1_7.json"))
        .expect("must parse");
    let result: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();

    report::check::all(&("", result.clone()), &sbom);

    let result = result.lock();

    println!("{result:#?}");

    assert_eq!(result.len(), 0);
}

#[cfg(any(feature = "cyclonedx-bom", feature = "serde-cyclonedx"))]
#[test]
fn issue_57_inspect() {
    let sbom = sbom_walker::Sbom::try_parse_any(include_bytes!("data/issue_57/sbom.json"))
        .expect("must parse");
    let result: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();

    report::check::all(&("", result.clone()), &sbom);

    let result = result.lock();

    println!("{result:#?}");

    assert_eq!(result.len(), 0);
}
