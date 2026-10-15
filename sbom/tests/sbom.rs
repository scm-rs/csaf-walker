#[cfg(feature = "serde-cyclonedx")]
use {
    parking_lot::Mutex,
    sbom_walker::report,
    std::{collections::BTreeMap, sync::Arc},
};

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
    let citations = sbom.citations.as_ref().expect("must retain citations");
    assert_eq!(citations.len(), 1);
    assert_eq!(
        citations[0].note.as_deref(),
        Some("Version reported by the build tool")
    );
    let citation = serde_json::to_value(&citations[0]).unwrap();
    assert_eq!(
        citation["pointers"],
        serde_json::json!(["/components/0/version"])
    );
}

/// Round-trip the versioned walker wrapper without dropping 1.7 fields or dependencies.
#[cfg(feature = "serde-cyclonedx")]
#[test]
fn cyclonedx_v17_wrapper_round_trip() {
    use sbom_walker::model::sbom::serde_cyclonedx::Sbom;

    let fixture = include_bytes!("data/cyclonedx.v1_7.json");
    let input: serde_json::Value = serde_json::from_slice(fixture).unwrap();
    let parsed: Sbom<'static> = serde_json::from_slice(fixture).unwrap();
    let serialized = serde_json::to_value(&parsed).unwrap();
    assert_eq!(serialized["citations"], input["citations"]);
    assert_eq!(serialized["dependencies"], input["dependencies"]);

    let round_trip: Sbom<'static> = serde_json::from_value(serialized).unwrap();
    assert_eq!(round_trip, parsed);
    assert!(matches!(round_trip, Sbom::V1_7(_)));
}

/// Dispatch older specifications to their own models, not to the newest schema.
#[cfg(feature = "serde-cyclonedx")]
#[test]
fn cyclonedx_older_version_dispatch() {
    use sbom_walker::{Sbom as ParsedSbom, model::sbom::serde_cyclonedx::Sbom};

    for version in ["1.4", "1.5", "1.6"] {
        let json = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": version,
            "version": 1,
            "components": [{"type": "library", "name": "older", "version": "1.0"}]
        });
        let parsed = ParsedSbom::try_parse_any(&serde_json::to_vec(&json).unwrap())
            .expect("must parse older specification");
        assert!(matches!(
            (version, &parsed),
            ("1.4", ParsedSbom::SerdeCycloneDx(Sbom::V1_4(_)))
                | ("1.5", ParsedSbom::SerdeCycloneDx(Sbom::V1_5(_)))
                | ("1.6", ParsedSbom::SerdeCycloneDx(Sbom::V1_6(_)))
        ));
        let serialized = match parsed {
            ParsedSbom::SerdeCycloneDx(parsed) => serde_json::to_value(parsed).unwrap(),
            #[cfg(any(feature = "spdx-rs", feature = "cyclonedx-bom"))]
            _ => panic!("must use serde CycloneDX model"),
        };
        assert_eq!(serialized["specVersion"], version);
        assert_eq!(serialized["components"][0]["name"], "older");
    }
}

#[cfg(feature = "serde-cyclonedx")]
fn cyclonedx_reference_document(version: &str) -> serde_json::Value {
    serde_json::json!({
        "bomFormat": "CycloneDX", "specVersion": version, "version": 1,
        "metadata": {"component": {
            "bom-ref": "root", "type": "application", "name": "root",
            "components": [{
                "bom-ref": "metadata-child", "type": "library", "name": "metadata-child"
            }]
        }},
        "components": [{
            "bom-ref": "component", "type": "library", "name": "component",
            "components": [{
                "bom-ref": "component-child", "type": "library", "name": "component-child"
            }]
        }],
        "services": [{
            "bom-ref": "service", "name": "service",
            "services": [{"bom-ref": "service-child", "name": "service-child"}]
        }],
        "dependencies": [
            {"ref": "root", "dependsOn": ["metadata-child", "component", "service"]},
            {"ref": "component", "dependsOn": ["component-child"]},
            {"ref": "service", "dependsOn": ["service-child"]}
        ]
    })
}

/// Exercise reference and dependency adapters for every selected schema, including 1.5.
#[cfg(feature = "serde-cyclonedx")]
#[test]
fn cyclonedx_nested_references_and_dependencies() {
    use sbom_walker::model::sbom::serde_cyclonedx::Sbom;

    for version in ["1.4", "1.5", "1.6", "1.7"] {
        let parsed: Sbom<'static> =
            serde_json::from_value(cyclonedx_reference_document(version)).unwrap();
        let references = parsed.bom_refs();
        assert_eq!(references.len(), 6);
        for reference in [
            "root",
            "metadata-child",
            "component",
            "component-child",
            "service",
            "service-child",
        ] {
            assert_eq!(references.get(reference), Some(&1), "version {version}");
        }
        let dependencies = parsed.dependencies().expect("must expose dependencies");
        assert_eq!(dependencies.len(), 3);
        for (dependency, (source, targets)) in dependencies.iter().zip([
            ("root", vec!["metadata-child", "component", "service"]),
            ("component", vec!["component-child"]),
            ("service", vec!["service-child"]),
        ]) {
            assert_eq!(dependency.r#ref(), source, "version {version}");
            assert_eq!(
                dependency.dependencies(),
                Some(targets),
                "version {version}"
            );
        }

        let result: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();
        report::check::serde_cyclonedx::all(&("", result.clone()), &parsed);
        assert!(result.lock().is_empty(), "version {version}");
    }
}

/// Invalid references must produce findings, not silently bypass dependency checks.
#[cfg(feature = "serde-cyclonedx")]
#[test]
fn cyclonedx_reports_duplicate_and_missing_references() {
    use sbom_walker::model::sbom::serde_cyclonedx::Sbom;

    for version in ["1.4", "1.5", "1.6", "1.7"] {
        let mut document = cyclonedx_reference_document(version);
        document["components"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "bom-ref": "root", "type": "library", "name": "duplicate-root"
            }));
        document["dependencies"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "ref": "missing-source", "dependsOn": ["missing-target"]
            }));
        let parsed: Sbom<'static> = serde_json::from_value(document).unwrap();
        let result: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();
        report::check::serde_cyclonedx::all(&("", result.clone()), &parsed);
        let mut messages = result
            .lock()
            .get("")
            .expect("must report invalid references")
            .clone();
        messages.sort();
        assert_eq!(
            messages,
            [
                "Duplicate bom-ref 'root', occurred 2 times.",
                "Missing left-side dependency reference: missing-source",
                "Missing right-side dependency reference: missing-target",
            ],
            "version {version}"
        );
    }
}

#[cfg(feature = "serde-cyclonedx")]
#[test]
fn cyclonedx_rejects_missing_or_unsupported_version() {
    use sbom_walker::model::sbom::serde_cyclonedx::Sbom;

    for json in [
        serde_json::json!({"bomFormat": "CycloneDX", "specVersion": "1.8"}),
        serde_json::json!({"bomFormat": "CycloneDX"}),
    ] {
        assert!(serde_json::from_value::<Sbom<'static>>(json).is_err());
    }
}

#[cfg(feature = "serde-cyclonedx")]
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

#[cfg(feature = "serde-cyclonedx")]
#[test]
fn cyclonedx_v17_top_level_checker_reports_invalid_dependency_ref() {
    let mut document: serde_json::Value =
        serde_json::from_slice(include_bytes!("data/cyclonedx.v1_7.json")).unwrap();
    document["dependencies"][0]["dependsOn"][0] = serde_json::json!("missing-target");
    let sbom = sbom_walker::Sbom::try_parse_any(&serde_json::to_vec(&document).unwrap())
        .expect("must parse");
    let result: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();

    report::check::all(&("", result.clone()), &sbom);

    assert_eq!(
        result
            .lock()
            .get("")
            .expect("must report the invalid dependency reference"),
        &["Missing right-side dependency reference: missing-target"]
    );
}

#[cfg(feature = "serde-cyclonedx")]
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
