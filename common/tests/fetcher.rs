use reqwest::StatusCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use walker_common::fetcher::{Fetcher, FetcherOptions};

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
async fn test_rate_limit_with_retry_after() {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst);

        // First request returns 429 with Retry-After
        if count == 0 {
            hyper::Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", "1")
                .body("Rate limited".to_string())
                .unwrap()
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

    // Should have waited at least 1 second (the Retry-After value)
    assert!(
        elapsed >= Duration::from_secs(1),
        "Expected at least 1s wait, got {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_rate_limit_without_retry_after() {
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

    // Should have waited at least 10 seconds (the default when no Retry-After header)
    assert!(
        elapsed >= Duration::from_secs(10),
        "Expected at least 10s wait (default), got {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_exponential_backoff() {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        let count = attempt_count_clone.fetch_add(1, Ordering::SeqCst);

        // Fail first 2 attempts with non-429 errors
        if count < 2 {
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

    let fetcher = Fetcher::new(FetcherOptions::new().retries(5))
        .await
        .unwrap();

    let result: String = fetcher.fetch(&server).await.unwrap();

    assert_eq!(result, "Success");
    assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_retry_exhaustion() {
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_clone = attempt_count.clone();

    let server = start_mock_server(move |_req| {
        attempt_count_clone.fetch_add(1, Ordering::SeqCst);
        hyper::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Always fails".to_string())
            .unwrap()
    })
    .await;

    let fetcher = Fetcher::new(FetcherOptions::new().retries(2))
        .await
        .unwrap();

    let result: Result<String, _> = fetcher.fetch(&server).await;

    assert!(result.is_err());
    // Should attempt initial + 2 retries = 3 total
    assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
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

#[tokio::test]
async fn test_configurable_default_retry_after() {
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

    // Configure a custom default of 2 seconds
    let fetcher = Fetcher::new(
        FetcherOptions::new()
            .retries(3)
            .default_retry_after(Duration::from_secs(2)),
    )
    .await
    .unwrap();

    let start = std::time::Instant::now();
    let result: String = fetcher.fetch(&server).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result, "Success");
    assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

    // Should have waited at least 2 seconds (our custom default)
    assert!(
        elapsed >= Duration::from_secs(2),
        "Expected at least 2s wait (custom default), got {:?}",
        elapsed
    );

    // Should not have waited 10 seconds (the default)
    assert!(
        elapsed < Duration::from_secs(10),
        "Expected less than 10s, got {:?}",
        elapsed
    );
}
