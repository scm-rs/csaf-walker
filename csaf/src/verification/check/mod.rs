use crate::verification::check::{
    base::{check_csaf_base, check_csaf_document_tracking_revision_history},
    informational_advisory::check_vulnerabilities_not_exits,
    security_incident_response::{check_csaf_document_notes, check_csaf_document_references},
    vex::{
        check_all_products_v11ies_exits_in_product_tree,
        check_branches_relationships_product_match, check_csaf_vex, check_history,
        check_vulnerabilities_cve_ids, check_vulnerabilities_product_status,
        check_vulnerabilities_size,
    },
};
use async_trait::async_trait;
use csaf::Csaf;
use std::borrow::Cow;

pub mod base;
pub mod informational_advisory;
pub mod security_advisory;
pub mod security_incident_response;
pub mod vex;

pub type CheckError = Cow<'static, str>;

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>>;
}

/// Implementation to allow a simple function style check
#[async_trait(?Send)]
impl<F> Check for F
where
    F: Fn(&Csaf) -> Vec<CheckError>,
{
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>> {
        Ok((self)(csaf))
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

pub fn init_verifying_visitor() -> Vec<(&'static str, Box<dyn Check>)> {
    vec![
        (
            "check_vulnerabilities_not_exits",
            Box::new(check_vulnerabilities_not_exits),
        ),
        (
            "check_csaf_document_notes",
            Box::new(check_csaf_document_notes),
        ),
        (
            "check_csaf_document_references",
            Box::new(check_csaf_document_references),
        ),
        ("check_csaf_base", Box::new(check_csaf_base)),
        (
            "check_csaf_document_tracking_revision_history",
            Box::new(check_csaf_document_tracking_revision_history),
        ),
        (
            "check_vulnerabilities_size",
            Box::new(check_vulnerabilities_size),
        ),
        (
            "check_vulnerabilities_product_status",
            Box::new(check_vulnerabilities_product_status),
        ),
        (
            "check_vulnerabilities_cve_ids",
            Box::new(check_vulnerabilities_cve_ids),
        ),
        (
            "check_all_products_v11ies_exits_in_product_tree",
            Box::new(check_all_products_v11ies_exits_in_product_tree),
        ),
        ("check_history", Box::new(check_history)),
        ("check_csaf_vex", Box::new(check_csaf_vex)),
        (
            "check_branches_relationships_product_match",
            Box::new(check_branches_relationships_product_match),
        ),
    ]
}
