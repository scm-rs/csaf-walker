use reqwest::StatusCode;
use rstest::rstest;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use walker_common::fetcher::{Error, Fetcher, FetcherOptions};

/// Test helper to start a mock HTTP server
async fn start_mock_server<F>(handler: F) -> String
where
    F: Fn(hyper::Request<hyper::body::Incoming>) -> hyper::Response<String> + Send + Sync + 'static,
{
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let handler = handler.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req)) }
                });

                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn test_successful_fetch() {
    let server = start_mock_server(|_req| {
        hyper::Response::builder()
            .status(StatusCode::OK)
            .body("Hello, World!".to_string())
            .unwrap()
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new()).await.unwrap();
    let result: String = fetcher.fetch(&server).await.unwrap();
    assert_eq!(result, "Hello, World!");
}

#[tokio::test]
async fn test_404_should_not_retry() {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        attempt_count_clone.fetch_add(1, Ordering::SeqCst);
        let builder = hyper::Response::builder().status(StatusCode::NOT_FOUND);
        builder.body("Not found".to_string()).unwrap()
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new().retries(2))
        .await
        .unwrap();

    let result: Result<String, Error> = fetcher.fetch(&server).await;
    match result {
        Err(Error::ClientError(code)) => assert_eq!(code, StatusCode::NOT_FOUND),
        other => panic!("expected ClientError(404), got {other:?}"),
    }
    assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
}

/// If the result data is `Option`, it should be `None` with 404, not an error.
#[tokio::test]
async fn test_404_should_not_retry_optional_ok() {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        attempt_count_clone.fetch_add(1, Ordering::SeqCst);
        let builder = hyper::Response::builder().status(StatusCode::NOT_FOUND);
        builder.body("Not found".to_string()).unwrap()
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new().retries(2))
        .await
        .unwrap();

    let result = fetcher.fetch::<Option<String>>(&server).await;
    match result {
        Ok(None) => {}
        other => panic!("expected Ok(None), got {other:?}"),
    }
    assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
}

#[rstest]
#[case::with_retry_after_header(Some("1"), 1)]
#[case::without_retry_after_header(None, 10)]
#[tokio::test]
async fn test_rate_limit_retry_after(
    #[case] retry_after_header: Option<&str>,
    #[case] expected_min_wait_secs: u64,
) {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();
    let retry_after_header = retry_after_header.map(String::from);

    let server = start_mock_server(move |_req| {
        let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst);

        // First request returns 429
        if count == 0 {
            let mut builder = hyper::Response::builder().status(StatusCode::TOO_MANY_REQUESTS);

            if let Some(ref header_value) = retry_after_header {
                builder = builder.header("Retry-After", header_value.as_str());
            }

            builder.body("Rate limited".to_string()).unwrap()
        } else {
            // Subsequent requests succeed
            hyper::Response::builder()
                .status(StatusCode::OK)
                .body("Success after retry".to_string())
                .unwrap()
        }
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new().retries(3))
        .await
        .unwrap();

    let start = std::time::Instant::now();
    let result: String = fetcher.fetch(&server).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result, "Success after retry");
    assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

    // Should have waited at least the expected duration
    assert!(
        elapsed >= Duration::from_secs(expected_min_wait_secs),
        "Expected at least {}s wait, got {:?}",
        expected_min_wait_secs,
        elapsed
    );
}

#[rstest]
#[case::succeeds_after_retries(2, 5, true, 3)]
#[case::exhausts_retries(usize::MAX, 2, false, 3)]
#[tokio::test]
async fn test_retry_behavior(
    #[case] fail_until: usize,
    #[case] max_retries: usize,
    #[case] should_succeed: bool,
    #[case] expected_attempts: usize,
) {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst);

        if count < fail_until {
            hyper::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Server error".to_string())
                .unwrap()
        } else {
            hyper::Response::builder()
                .status(StatusCode::OK)
                .body("Success".to_string())
                .unwrap()
        }
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new().retries(max_retries))
        .await
        .unwrap();

    let result: Result<String, _> = fetcher.fetch(&server).await;

    assert_eq!(result.is_ok(), should_succeed);
    if should_succeed {
        assert_eq!(result.unwrap(), "Success");
    }
    assert_eq!(attempt_count.load(Ordering::SeqCst), expected_attempts);
}

#[tokio::test]
async fn test_multiple_rate_limits() {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst);

        // Return 429 for first two attempts
        if count < 2 {
            hyper::Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", "1")
                .body("Rate limited".to_string())
                .unwrap()
        } else {
            hyper::Response::builder()
                .status(StatusCode::OK)
                .body("Success".to_string())
                .unwrap()
        }
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new().retries(5))
        .await
        .unwrap();

    let start = std::time::Instant::now();
    let result: String = fetcher.fetch(&server).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result, "Success");
    assert_eq!(attempt_count.load(Ordering::SeqCst), 3);

    // Should have waited at least 2 seconds (1 second for each 429)
    assert!(
        elapsed >= Duration::from_secs(2),
        "Expected at least 2s wait, got {:?}",
        elapsed
    );
}

#[rstest]
#[case::custom_default_2_seconds(2)]
#[case::custom_default_3_seconds(3)]
#[tokio::test]
async fn test_configurable_default_retry_after(#[case] custom_default_secs: u64) {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst);

        // First request returns 429 without Retry-After header
        if count == 0 {
            hyper::Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body("Rate limited".to_string())
                .unwrap()
        } else {
            hyper::Response::builder()
                .status(StatusCode::OK)
                .body("Success".to_string())
                .unwrap()
        }
    })
    .await;

    let fetcher = Fetcher::new(
        FetcherOptions::new()
            .retries(3)
            .retry_after(Duration::from_secs(custom_default_secs)),
    )
    .await
    .unwrap();

    let start = std::time::Instant::now();
    let result: String = fetcher.fetch(&server).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result, "Success");
    assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

    // Should have waited at least the custom default
    assert!(
        elapsed >= Duration::from_secs(custom_default_secs),
        "Expected at least {}s wait (custom default), got {:?}",
        custom_default_secs,
        elapsed
    );

    // Should not have waited 10 seconds (the standard default)
    assert!(
        elapsed < Duration::from_secs(10),
        "Expected less than 10s, got {:?}",
        elapsed
    );
}
