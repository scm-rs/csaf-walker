use crate::report::ReportSink;
use cyclonedx_bom::prelude::*;
use std::collections::HashMap;

/// Run all CycloneDX sbom checks
pub fn all(report: &dyn ReportSink, sbom: &Bom) {
    CycloneDxChecks { report, sbom }.all();
}

struct CycloneDxChecks<'c> {
    report: &'c dyn ReportSink,
    sbom: &'c Bom,
}

impl CycloneDxChecks<'_> {
    /// Run all checks
    pub fn all(&self) {
        log::debug!("Running all CycloneDX checks");

        self.duplicate_components();
        self.missing_bom_refs();
    }

    fn collect_bom_refs(&self) -> HashMap<&str, usize> {
        let mut bom_refs = HashMap::<_, usize>::new();

        if let Some(bom_ref) = self
            .sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.component.as_ref())
            .and_then(|component| component.bom_ref.as_ref())
        {
            *bom_refs.entry(bom_ref.as_str()).or_default() += 1;
        }

        for component in self.sbom.components.iter().flat_map(|c| &c.0) {
            if let Some(bom_ref) = &component.bom_ref {
                *bom_refs.entry(bom_ref.as_str()).or_default() += 1;
            }
        }

        for service in self.sbom.services.iter().flat_map(|c| &c.0) {
            if let Some(bom_ref) = &service.bom_ref {
                *bom_refs.entry(bom_ref.as_str()).or_default() += 1;
            }
        }

        bom_refs
    }

    /// Ensure that all bom-refs are unique.
    ///
    /// > An optional identifier which can be used to reference the component elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.
    pub fn duplicate_components(&self) {
        log::debug!("Checking component duplicates");

        let bom_refs = self.collect_bom_refs();

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

        let bom_refs = self.collect_bom_refs();

        for deps in self.sbom.dependencies.iter().flat_map(|d| &d.0) {
            if !bom_refs.contains_key(&*deps.dependency_ref) {
                self.report.error(format!(
                    "Missing left-side dependency reference: {}",
                    deps.dependency_ref
                ));
            }
            for right in &deps.dependencies {
                if !bom_refs.contains_key(right.as_str()) {
                    self.report
                        .error(format!("Missing right-side dependency reference: {right}",));
                }
            }
        }
    }
}
