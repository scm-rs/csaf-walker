//! Reporting functionality

mod render;

pub use render::*;

use crate::discover::DiscoveredAdvisory;
use crate::source::{DispatchSource, DispatchSourceError, HttpSourceError};
use crate::validation::{ValidatedAdvisory, ValidationError};
use crate::verification::VerificationError;
use reqwest::StatusCode;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use url::Url;
use walker_common::{fetcher, retrieve::RetrievalError, utils::url::Urlify};

#[derive(Clone, Debug)]
pub struct ReportResult<'d> {
    pub total: usize,
    pub duplicates: &'d Duplicates,
    pub errors: &'d BTreeMap<DocumentKey, String>,
    pub warnings: &'d BTreeMap<DocumentKey, Vec<Cow<'static, str>>>,
    /// Documents that could not be retrieved due to allowed client errors (e.g. 404).
    pub ignored_errors: &'d BTreeMap<DocumentKey, StatusCode>,
}

#[derive(Clone, Debug, Default)]
pub struct Duplicates {
    pub duplicates: BTreeMap<DocumentKey, usize>,
    pub known: HashSet<DocumentKey>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DocumentKey {
    /// the URL to the distribution folder
    pub distribution_url: Url,
    /// the URL to the document, relative to the `distribution_url`.
    pub url: String,
}

impl DocumentKey {
    pub fn for_document(advisory: &DiscoveredAdvisory) -> Self {
        Self {
            distribution_url: advisory.url.clone(),
            url: advisory.possibly_relative_url(),
        }
    }
}

/// Extract the HTTP client error status code from a verification error, if present.
///
/// This unwraps the error chain: `VerificationError::Upstream` → `ValidationError::Retrieval`
/// → `RetrievalError::Source` → `DispatchSourceError::Http` → `HttpSourceError::Fetcher`
/// → `fetcher::Error::ClientError(status)`.
pub fn get_client_error_status(
    err: &VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>,
) -> Option<StatusCode> {
    let VerificationError::Upstream(validation_err) = err else {
        return None;
    };
    let ValidationError::Retrieval(retrieval_err) = validation_err else {
        return None;
    };
    let RetrievalError::Source { err, .. } = retrieval_err;
    let DispatchSourceError::Http(HttpSourceError::Fetcher(fetcher::Error::ClientError(status))) =
        err
    else {
        return None;
    };
    Some(*status)
}
