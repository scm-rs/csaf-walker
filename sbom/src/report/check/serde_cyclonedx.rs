use crate::{model::sbom::serde_cyclonedx::Sbom, report::ReportSink};

/// Run all CycloneDX sbom checks
pub fn all(report: &dyn ReportSink, sbom: &Sbom) {
    CycloneDxChecks { report, sbom }.all();
}

struct CycloneDxChecks<'c> {
    report: &'c dyn ReportSink,
    sbom: &'c Sbom<'c>,
}

impl CycloneDxChecks<'_> {
    /// Run all checks
    pub fn all(&self) {
        log::debug!("Running all CycloneDX checks");

        self.duplicate_components();
        self.missing_bom_refs();
    }

    /// Ensure that all bom-refs are unique.
    ///
    /// > An optional identifier which can be used to reference the component elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.
    pub fn duplicate_components(&self) {
        log::debug!("Checking component duplicates");

        let bom_refs = self.sbom.bom_refs();

        for (bom_ref, num) in bom_refs {
            if num > 1 {
                self.report.error(format!(
                    "Duplicate bom-ref '{bom_ref}', occurred {num} times."
                ));
            }
        }
    }

    /// Ensure that all bom-refs are present.
    pub fn missing_bom_refs(&self) {
        log::debug!("Check for missing bom-ref targets");

        let bom_refs = self.sbom.bom_refs();

        for deps in self.sbom.dependencies().iter().flatten() {
            if !bom_refs.contains_key(deps.r#ref()) {
                self.report.error(format!(
                    "Missing left-side dependency reference: {}",
                    deps.r#ref()
                ));
            }
            for right in deps.dependencies().iter().flatten() {
                if !bom_refs.contains_key(right) {
                    self.report
                        .error(format!("Missing right-side dependency reference: {right}",));
                }
            }
        }
    }
}
