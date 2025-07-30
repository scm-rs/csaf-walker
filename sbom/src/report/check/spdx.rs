use crate::report::ReportSink;
use spdx_rs::models::{RelationshipType, SPDX};
use std::collections::{HashMap, HashSet};

/// Run all SPDX sbom checks
pub fn all(report: &dyn ReportSink, spdx: &SPDX) {
    SpdxChecks { report, spdx }.all();
}

struct SpdxChecks<'c> {
    report: &'c dyn ReportSink,
    spdx: &'c SPDX,
}

impl SpdxChecks<'_> {
    /// run all checks
    pub fn all(&self) {
        log::debug!("Running all SPDX checks");

        self.rel_targets();
        self.duplicate_packages();
    }

    /// check for duplicate nodes
    fn duplicate_packages(&self) {
        log::debug!("Checking duplicates IDs");

        let mut ids = HashMap::with_capacity(
            self.spdx.package_information.len() + self.spdx.file_information.len() + 1,
        );

        ids.insert(&self.spdx.document_creation_information.spdx_identifier, 1);

        for package in &self.spdx.package_information {
            *ids.entry(&package.package_spdx_identifier).or_default() += 1;
        }
        for file in &self.spdx.file_information {
            *ids.entry(&file.file_spdx_identifier).or_default() += 1;
        }

        for (id, num) in ids {
            if num > 1 {
                self.report
                    .error(format!("Duplicate SPDX ID '{id}', occurred {num} times."));
            }
        }
    }

    /// check if all relationships have valid targets
    fn rel_targets(&self) {
        log::debug!("Checking valid relationship targets");

        // packages

        let mut ids = self
            .spdx
            .package_information
            .iter()
            .map(|p| p.package_spdx_identifier.as_str())
            .collect::<HashSet<_>>();

        // files

        ids.extend(
            self.spdx
                .file_information
                .iter()
                .map(|f| f.file_spdx_identifier.as_str()),
        );

        // document itself

        ids.insert(&self.spdx.document_creation_information.spdx_identifier);

        // external references

        let doc_refs = self
            .spdx
            .document_creation_information
            .external_document_references
            .iter()
            .map(|r| r.id_string.as_str())
            .collect::<HashSet<_>>();

        // now see if all relationships have valid targets

        for rel in &self.spdx.relationships {
            self.check_id(
                &ids,
                &doc_refs,
                &rel.spdx_element_id,
                &rel.spdx_element_id,
                &rel.relationship_type,
                &rel.related_spdx_element,
            );
            self.check_id(
                &ids,
                &doc_refs,
                &rel.related_spdx_element,
                &rel.spdx_element_id,
                &rel.relationship_type,
                &rel.related_spdx_element,
            );
        }
    }

    /// check if an ID is known, unless it's an external.
    fn check_id(
        &self,
        ids: &HashSet<&str>,
        doc_refs: &HashSet<&str>,
        id: &str,
        left: &str,
        rel: &RelationshipType,
        right: &str,
    ) {
        match (id, id.split_once(":")) {
            ("NONE" | "NOASSERTION", _) => {
                // no check
                return;
            }
            (_, Some((doc_ref, _id))) if doc_ref.starts_with("DocumentRef-") => {
                if !doc_refs.contains(doc_ref) {
                    self.report.error(format!(
                        "Invalid document reference '{doc_ref}' of relationship '{left}' -[{rel:?}]-> '{right}'",
                    ));
                }
                // we can't check the ID, as we don't have the target document
            }
            _ => {
                if !ids.contains(id) {
                    self.report.error(format!(
                        "Invalid reference '{id}' of relationship '{left}' -[{rel:?}]-> '{right}'",
                    ));
                }
            }
        }

        if !ids.contains(id) {
            self.report.error(format!(
                "Invalid reference '{id}' of relationship '{left}' -[{rel:?}]-> '{right}'",
            ));
        }
    }
}
