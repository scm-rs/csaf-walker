use std::time::Duration;

use reqwest::{Response, StatusCode, header};

/// Parse Retry-After header value
fn parse_retry_after(value: &str) -> Option<Duration> {
    // Try parsing as seconds (numeric)
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    // Could also parse HTTP-date format here if needed
    None
}

pub fn get_retry_after_from_response_header(
    response: &Response,
    default_duration: Duration,
) -> Option<Duration> {
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after)
            .unwrap_or(default_duration);
        return Some(retry_after);
    }
    None
}
