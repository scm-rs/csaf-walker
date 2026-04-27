use csaf_walker::{
    discover::AsDiscovered,
    report::{DocumentKey, Duplicates, get_client_error_status},
    retrieve::RetrievingVisitor,
    source::{DispatchSource, HttpOptions, HttpSource},
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{
        VerificationError, VerifiedAdvisory, VerifyingVisitor,
        check::{CheckError, init_verifying_visitor},
    },
    visitors::duplicates::DetectDuplicatesVisitor,
    walker::Walker,
};
use reqwest::{StatusCode, Url};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use walker_common::{
    fetcher::{Fetcher, FetcherOptions},
    utils::url::Urlify,
    validate::ValidationOptions,
};

const PROVIDER_METADATA_TEMPLATE: &str = r#"{
    "canonical_url": "CANONICAL_URL",
    "distributions": [{
        "directory_url": "DIST_URL"
    }],
    "last_updated": "2024-01-01T00:00:00Z",
    "list_on_CSAF_aggregators": false,
    "metadata_version": "2.0",
    "mirror_on_CSAF_aggregators": false,
    "public_openpgp_keys": [],
    "publisher": {
        "category": "vendor",
        "contact_details": "test@example.com",
        "name": "Test Corp",
        "namespace": "https://example.com"
    },
    "role": "csaf_provider"
}"#;

const GOOD_ADVISORY: &str = r#"{
    "document": {
        "category": "csaf_base",
        "csaf_version": "2.0",
        "title": "Test Advisory",
        "publisher": {
            "category": "vendor",
            "name": "Test Corp",
            "namespace": "https://example.com"
        },
        "tracking": {
            "id": "TEST-2024-001",
            "status": "final",
            "version": "1",
            "revision_history": [{"date":"2024-01-01T00:00:00Z","number":"1","summary":"Initial"}],
            "initial_release_date": "2024-01-01T00:00:00Z",
            "current_release_date": "2024-01-01T00:00:00Z"
        }
    }
}"#;

/// Start a mock HTTP server that:
/// - Serves provider-metadata.json at the root
/// - Serves changes.csv listing two advisories
/// - Returns 200 for good.json and 404 for missing.json
async fn start_csaf_mock_server() -> String {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let base_for_handler = base_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let base = base_for_handler.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let base = base.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let response = match path.as_str() {
                            "/provider-metadata.json" => {
                                let body = PROVIDER_METADATA_TEMPLATE
                                    .replace(
                                        "CANONICAL_URL",
                                        &format!("{base}/provider-metadata.json"),
                                    )
                                    .replace("DIST_URL", &format!("{base}/advisories/"));
                                hyper::Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json")
                                    .body(body)
                                    .unwrap()
                            }
                            "/advisories/changes.csv" => hyper::Response::builder()
                                .status(StatusCode::OK)
                                .body(
                                    "good.json,2024-01-01T00:00:00Z\nmissing.json,2024-01-01T00:00:00Z\n"
                                        .to_string(),
                                )
                                .unwrap(),
                            "/advisories/good.json" => hyper::Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "application/json")
                                .body(GOOD_ADVISORY.to_string())
                                .unwrap(),
                            // 404 for the advisory itself
                            "/advisories/missing.json" => hyper::Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body("Not found".to_string())
                                .unwrap(),
                            // .asc and .sha256/.sha512 files return 404 (treated as optional)
                            _ => hyper::Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body("Not found".to_string())
                                .unwrap(),
                        };
                        Ok::<_, Infallible>(response)
                    }
                });

                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    eprintln!("Error serving connection: {err:?}");
                }
            });
        }
    });

    base_url
}

/// Run the report visitor pipeline against a source with the given allowed client errors,
/// returning (errors, ignored_errors, total).
async fn run_report(
    source: DispatchSource,
    allowed_client_errors: HashSet<StatusCode>,
) -> (
    BTreeMap<DocumentKey, String>,
    BTreeMap<DocumentKey, StatusCode>,
    usize,
) {
    let total = Arc::new(AtomicUsize::default());
    let duplicates: Arc<Mutex<Duplicates>> = Default::default();
    let errors: Arc<Mutex<BTreeMap<DocumentKey, String>>> = Default::default();
    let warnings: Arc<Mutex<BTreeMap<DocumentKey, Vec<CheckError>>>> = Default::default();
    let ignored_errors: Arc<Mutex<BTreeMap<DocumentKey, StatusCode>>> = Default::default();

    {
        let total = total.clone();
        let errors = errors.clone();
        let warnings = warnings.clone();
        let ignored_errors = ignored_errors.clone();
        let duplicates = duplicates.clone();

        let visitor = move |advisory: Result<
            VerifiedAdvisory<ValidatedAdvisory, &'static str>,
            VerificationError<ValidationError<DispatchSource>, ValidatedAdvisory>,
        >| {
            (*total).fetch_add(1, Ordering::Release);

            let errors = errors.clone();
            let warnings = warnings.clone();
            let ignored_errors = ignored_errors.clone();
            let allowed_client_errors = allowed_client_errors.clone();

            async move {
                let adv = match advisory {
                    Ok(adv) => adv,
                    Err(err) => {
                        let name = match err.as_discovered().relative_base_and_url() {
                            Some((base, relative)) => DocumentKey {
                                distribution_url: base.clone(),
                                url: relative,
                            },
                            None => DocumentKey {
                                distribution_url: err.url().clone(),
                                url: Default::default(),
                            },
                        };

                        if let Some(status) = get_client_error_status(&err)
                            && allowed_client_errors.contains(&status)
                        {
                            ignored_errors.lock().await.insert(name, status);
                            return Ok::<_, anyhow::Error>(());
                        }

                        errors.lock().await.insert(name, err.to_string());
                        return Ok::<_, anyhow::Error>(());
                    }
                };

                if !adv.failures.is_empty() {
                    let name = DocumentKey::for_document(&adv);
                    warnings
                        .lock()
                        .await
                        .entry(name)
                        .or_default()
                        .extend(adv.failures.into_values().flatten());
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let visitor = VerifyingVisitor::with_checks(visitor, init_verifying_visitor());
        let visitor = ValidationVisitor::new(visitor).with_options(ValidationOptions::default());
        let visitor = RetrievingVisitor::new(source.clone(), visitor);
        let visitor = DetectDuplicatesVisitor {
            duplicates,
            visitor,
        };

        Walker::new(source)
            .with_progress(())
            .walk(visitor)
            .await
            .expect("walk should succeed");
    }

    let total = total.load(Ordering::Acquire);
    let errors = errors.lock().await.clone();
    let ignored_errors = ignored_errors.lock().await.clone();

    (errors, ignored_errors, total)
}

#[tokio::test]
async fn report_with_allow_missing_classifies_404_as_ignored() {
    let base_url = start_csaf_mock_server().await;

    let metadata_url = Url::parse(&format!("{base_url}/provider-metadata.json")).unwrap();
    let fetcher = Fetcher::new(FetcherOptions::default()).await.unwrap();
    let source: DispatchSource =
        HttpSource::new(metadata_url, fetcher, HttpOptions::default()).into();

    let mut allowed = HashSet::new();
    allowed.insert(StatusCode::NOT_FOUND);

    let (errors, ignored_errors, total) = run_report(source, allowed).await;

    assert_eq!(total, 2, "should process both advisories");
    assert!(
        errors.is_empty(),
        "no hard errors expected, got: {errors:?}"
    );
    assert_eq!(
        ignored_errors.len(),
        1,
        "one ignored error expected for missing.json"
    );

    let (key, status) = ignored_errors.iter().next().unwrap();
    assert_eq!(*status, StatusCode::NOT_FOUND);
    assert!(
        key.url.contains("missing.json"),
        "ignored error should be for missing.json, got: {}",
        key.url
    );
}

#[tokio::test]
async fn report_without_allow_missing_treats_404_as_error() {
    let base_url = start_csaf_mock_server().await;

    let metadata_url = Url::parse(&format!("{base_url}/provider-metadata.json")).unwrap();
    let fetcher = Fetcher::new(FetcherOptions::default()).await.unwrap();
    let source: DispatchSource =
        HttpSource::new(metadata_url, fetcher, HttpOptions::default()).into();

    // No allowed client errors
    let (errors, ignored_errors, total) = run_report(source, HashSet::new()).await;

    assert_eq!(total, 2, "should process both advisories");
    assert!(
        ignored_errors.is_empty(),
        "no ignored errors expected without allow-missing"
    );
    assert_eq!(errors.len(), 1, "one hard error expected for missing.json");

    let (key, _msg) = errors.iter().next().unwrap();
    assert!(
        key.url.contains("missing.json"),
        "error should be for missing.json, got: {}",
        key.url
    );
}
