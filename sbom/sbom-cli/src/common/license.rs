use sbom_walker::report::ReportSink;
use serde_json::Value;

/// Check the document for invalid SPDX license expressions and replace them with `NOASSERTION`.
pub fn fix_license(report: &dyn ReportSink, mut json: Value) -> (Value, bool) {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str()
                && let Err(err) = spdx_expression::SpdxExpression::parse(declared)
            {
                report.error(format!("Faulty SPDX license expression: {err}"));
                package["licenseDeclared"] = "NOASSERTION".into();
                changed = true;
            }
        }
    }

    (json, changed)
}
