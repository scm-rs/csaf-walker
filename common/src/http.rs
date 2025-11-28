use std::time::Duration;

use reqwest::{Response, StatusCode, header};

pub enum RetryAfter {
    Duration(Duration),
    After(std::time::SystemTime),
}

/// Parse Retry-After header value.
/// Supports both delay-seconds (numeric) and HTTP-date formats as per RFC7231
fn parse_retry_after(value: &str) -> Option<RetryAfter> {
    // Try parsing as seconds (numeric)
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(RetryAfter::Duration(Duration::from_secs(seconds)));
    }

    // Try parsing as HTTP-date (RFC7231 format)
    // Common formats: "Sun, 06 Nov 1994 08:49:37 GMT" (IMF-fixdate preferred)
    if let Ok(datetime) = httpdate::parse_http_date(value) {
        return Some(RetryAfter::After(datetime));
    }

    None
}

pub fn calculate_retry_after_from_response_header(
    response: &Response,
    default_duration: Duration,
) -> Option<Duration> {
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after)
            .and_then(|retry| match retry {
                RetryAfter::Duration(d) => Some(d),
                RetryAfter::After(after) => {
                    // Calculate duration from now until the specified time
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .and_then(|now| {
                            after
                                .duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .and_then(|target| target.checked_sub(now))
                        })
                }
            })
            .unwrap_or(default_duration);
        return Some(retry_after);
    }
    None
}
