use parking_lot::Mutex;
use sbom_walker::report;
use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "cyclonedx-bom")]
#[test]
fn test_cyclonedx_v13_json() {
    let _ = sbom_walker::Sbom::try_cyclonedx_json(include_bytes!("data/cyclonedx.v1_3.json"))
        .expect("must parse");
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
