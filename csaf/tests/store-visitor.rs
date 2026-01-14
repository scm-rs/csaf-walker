use bytes::Bytes;
use csaf_walker::{
    discover::{DiscoveredAdvisory, DistributionContext},
    model::metadata::{Distribution, ProviderMetadata, Publisher, Role},
    retrieve::{RetrievedAdvisory, RetrievedVisitor},
    source::{FileSource, HttpSource, HttpSourceError},
    visitors::store::StoreVisitor,
};
use digest::Output;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::Sha256;
use std::{fs, rc::Rc, sync::Arc, time::Duration};
use tempfile::TempDir;
use time::OffsetDateTime;
use url::Url;
use walker_common::retrieve::{RetrievalError, RetrievalMetadata, RetrievedDigest};

/// Helper function to create a basic ProviderMetadata for testing
fn create_test_metadata() -> ProviderMetadata {
    ProviderMetadata {
        canonical_url: Url::parse("https://example.com/.well-known/csaf/provider-metadata.json")
            .unwrap(),
        distributions: vec![Distribution {
            directory_url: Some(Url::parse("https://example.com/advisories/").unwrap()),
            rolie: None,
        }],
        last_updated: chrono::Utc::now(),
        list_on_csaf_aggregators: false,
        metadata_version: "2.0".to_string(),
        mirror_on_csaf_aggregators: false,
        public_openpgp_keys: vec![],
        publisher: Publisher {
            category: "vendor".to_string(),
            contact_details: "security@example.com".to_string(),
            issuing_authority: None,
            name: "Example Corp".to_string(),
            namespace: "https://example.com".to_string(),
        },
        role: Role::Provider,
    }
}

/// Helper function to create a test DiscoveredAdvisory
fn create_test_discovered_advisory() -> DiscoveredAdvisory {
    let context = Arc::new(DistributionContext::Directory(
        Url::parse("https://example.com/advisories/").unwrap(),
    ));

    DiscoveredAdvisory {
        context,
        url: Url::parse("https://example.com/advisories/test-advisory-2024-001.json").unwrap(),
        digest: Some(
            Url::parse("https://example.com/advisories/test-advisory-2024-001.json.sha256")
                .unwrap(),
        ),
        signature: Some(
            Url::parse("https://example.com/advisories/test-advisory-2024-001.json.asc").unwrap(),
        ),
        modified: std::time::SystemTime::now(),
    }
}

/// Helper function to create a test RetrievedAdvisory
fn create_test_retrieved_advisory(discovered: DiscoveredAdvisory) -> RetrievedAdvisory {
    let test_data = r#"{
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test Advisory",
            "publisher": {
                "category": "vendor",
                "name": "Example Corp",
                "namespace": "https://example.com"
            },
            "tracking": {
                "id": "TEST-2024-001",
                "status": "final",
                "version": "1",
                "revision_history": [],
                "initial_release_date": "2024-01-01T00:00:00Z",
                "current_release_date": "2024-01-01T00:00:00Z"
            }
        }
    }"#;

    RetrievedAdvisory {
        discovered,
        data: Bytes::from(test_data),
        signature: Some("test-signature".to_string()),
        sha256: Some(RetrievedDigest {
            expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            actual: Output::<Sha256>::from([
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]),
        }),
        sha512: None,
        metadata: RetrievalMetadata {
            last_modification: Some(OffsetDateTime::now_utc()),
            etag: Some("test-etag".to_string()),
        },
    }
}

#[tokio::test]
async fn given_advisory_could_be_retrieved_when_it_should_be_stored_it_is_saved_to_disk() {
    // Setup temporary directory for storing files
    let temp_dir = TempDir::new().unwrap();
    let cut: StoreVisitor = StoreVisitor::new(temp_dir.path());

    // Create test metadata and context
    let metadata = create_test_metadata();
    let context = Rc::new(metadata);

    // Create test advisory
    let discovered = create_test_discovered_advisory();
    let retrieved = create_test_retrieved_advisory(discovered);
    let retrieved_advisory_result: Result<
        RetrievedAdvisory,
        RetrievalError<DiscoveredAdvisory, FileSource>,
    > = Ok(retrieved);

    // Test visit_advisory on StoreVisitor
    let result = cut
        .visit_advisory(&context, retrieved_advisory_result)
        .await;

    // Assert
    assert!(
        result.is_ok(),
        "visit_advisory should succeed: {:?}",
        result
    );

    // The file path uses URL encoding for the distribution base (same logic as distribution_base function)
    let distribution_url = "https://example.com/advisories/";
    let encoded_dir = utf8_percent_encode(distribution_url, NON_ALPHANUMERIC).to_string();
    let distribution_dir = temp_dir.path().join(encoded_dir);

    assert!(
        distribution_dir.exists(),
        "Distribution directory should exist at {:?}",
        distribution_dir
    );

    let expected_file = distribution_dir.join("test-advisory-2024-001.json");

    assert!(
        expected_file.exists(),
        "Advisory file should be created at {:?}",
        expected_file
    );
}

#[tokio::test]
async fn given_advisory_retrieval_fails_with_non_client_error_when_visiting_then_error_is_returned()
{
    // Setup temporary directory for storing files
    let temp_dir = TempDir::new().unwrap();
    let cut: StoreVisitor = StoreVisitor::new(temp_dir.path());

    // Create test metadata and context
    let metadata = create_test_metadata();
    let context = Rc::new(metadata);

    // Create test advisory with a non-client error (e.g., IO error, network timeout, etc.)
    let discovered = create_test_discovered_advisory();
    let error = RetrievalError::Source {
        discovered,
        err: anyhow::anyhow!("Network timeout"),
    };
    let retrieved_advisory_result: Result<
        RetrievedAdvisory,
        RetrievalError<DiscoveredAdvisory, FileSource>,
    > = Err(error);

    // Test visit_advisory on StoreVisitor
    let result = cut
        .visit_advisory(&context, retrieved_advisory_result)
        .await;

    // Assert - should return an error for non-client errors
    assert!(
        result.is_err(),
        "visit_advisory should return error for non-client errors"
    );

    // Verify the error is a retrieval error
    match result {
        Err(e) => {
            let error_string = e.to_string();
            assert!(
                error_string.contains("Network timeout") || error_string.contains("Retrieval"),
                "Error should indicate retrieval failure: {}",
                error_string
            );
        }
        Ok(_) => panic!("Expected error but got Ok"),
    }
}

#[tokio::test]
async fn given_advisory_retrieval_fails_with_client_error_and_allow_missing_is_set_when_visiting_then_no_error_is_returned()
 {
    // Setup temporary directory for storing files
    let temp_dir = TempDir::new().unwrap();
    let cut: StoreVisitor = StoreVisitor::new(temp_dir.path())
        .allow_client_errors_iter([reqwest::StatusCode::NOT_FOUND]);

    // Create test metadata and context
    let metadata = create_test_metadata();
    let context = Rc::new(metadata);

    // Create test advisory with a non-client error (e.g., IO error, network timeout, etc.)
    let discovered = create_test_discovered_advisory();
    let error = RetrievalError::Source {
        discovered,
        err: HttpSourceError::Fetcher(walker_common::fetcher::Error::ClientError(
            reqwest::StatusCode::NOT_FOUND,
        )),
    };
    let retrieved_advisory_result: Result<
        RetrievedAdvisory,
        RetrievalError<DiscoveredAdvisory, HttpSource>,
    > = Err(error);

    // Test visit_advisory on StoreVisitor
    let result = cut
        .visit_advisory(&context, retrieved_advisory_result)
        .await;

    // Assert - should return an error for non-client errors
    assert!(
        result.is_ok(),
        "visit_advisory should return ok for client errors"
    );

    // The file path uses URL encoding for the distribution base (same logic as distribution_base function)
    let distribution_url = "https://example.com/advisories/";
    let encoded_dir = utf8_percent_encode(distribution_url, NON_ALPHANUMERIC).to_string();
    let distribution_dir = temp_dir.path().join(encoded_dir);

    assert!(
        distribution_dir.exists(),
        "Distribution directory should exist at {:?}",
        distribution_dir
    );

    let expected_file = distribution_dir.join("test-advisory-2024-001.json.errors");

    // Assert - ensure the error file was written
    assert_eq!(
        fs::read_to_string(expected_file).expect("must be able to read error file"),
        r#"{"status_code":404}"#,
        "error file should contain structured JSON information"
    );
}

#[tokio::test]
async fn given_advisory_retrieval_fails_with_client_error_when_visiting_then_no_error_is_returned()
{
    // Setup temporary directory for storing files
    let temp_dir = TempDir::new().unwrap();
    let cut: StoreVisitor = StoreVisitor::new(temp_dir.path()).allow_client_errors_iter([]);

    // Create test metadata and context
    let metadata = create_test_metadata();
    let context = Rc::new(metadata);

    // Create test advisory with a non-client error (e.g., IO error, network timeout, etc.)
    let discovered = create_test_discovered_advisory();
    let error = RetrievalError::Source {
        discovered,
        err: HttpSourceError::Fetcher(walker_common::fetcher::Error::ClientError(
            reqwest::StatusCode::NOT_FOUND,
        )),
    };
    let retrieved_advisory_result: Result<
        RetrievedAdvisory,
        RetrievalError<DiscoveredAdvisory, HttpSource>,
    > = Err(error);

    // Test visit_advisory on StoreVisitor
    let result = cut
        .visit_advisory(&context, retrieved_advisory_result)
        .await;

    // Assert - should return an error for non-client errors
    assert!(
        result.is_err(),
        "visit_advisory should return ok for client errors"
    );

    match result {
        Err(e) => {
            let error_string = e.to_string();
            assert!(
                error_string.contains("Not Found"),
                "Error should indicate retrieval failure: {}",
                error_string
            );
        }
        Ok(_) => panic!("Expected error but got Ok"),
    }
}

#[tokio::test]
async fn given_advisory_retrieval_fails_with_non_client_error_in_http_source_when_visiting_then_error_is_returned()
 {
    // Setup temporary directory for storing files
    let temp_dir = TempDir::new().unwrap();
    let cut: StoreVisitor = StoreVisitor::new(temp_dir.path());

    // Create test metadata and context
    let metadata = create_test_metadata();
    let context = Rc::new(metadata);

    // Create test advisory with a non-client error (e.g., IO error, network timeout, etc.)
    let discovered = create_test_discovered_advisory();
    let error = RetrievalError::Source {
        discovered,
        err: HttpSourceError::Fetcher(walker_common::fetcher::Error::RateLimited(
            Duration::from_hours(1),
        )),
    };
    let retrieved_advisory_result: Result<
        RetrievedAdvisory,
        RetrievalError<DiscoveredAdvisory, HttpSource>,
    > = Err(error);

    // Test visit_advisory on StoreVisitor
    let result = cut
        .visit_advisory(&context, retrieved_advisory_result)
        .await;

    // Assert - should return an error for non-client errors
    assert!(
        result.is_err(),
        "visit_advisory should return error for non-client errors"
    );

    match result {
        Err(e) => {
            let error_string = e.to_string();
            assert!(
                error_string.contains("Rate limited"),
                "Error should indicate retrieval failure: {}",
                error_string
            );
        }
        Ok(_) => panic!("Expected error but got Ok"),
    }
}
