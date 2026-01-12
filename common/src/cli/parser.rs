use anyhow::Context;

/// Parses the allowed client errors from the command line arguments.
pub fn parse_allow_client_errors(
    allow_missing: bool,
    allow_client_errors: Vec<String>,
) -> anyhow::Result<Vec<reqwest::StatusCode>, anyhow::Error> {
    let allow_client_errors_str = if allow_missing && allow_client_errors.is_empty() {
        vec!["404".to_string()]
    } else {
        allow_client_errors
    };

    let allow_client_errors: Vec<reqwest::StatusCode> = allow_client_errors_str
        .into_iter()
        .map(|s| {
            s.parse::<u16>()
                .context(format!("Failed to parse '{}' as an integer.", s))
                .and_then(|code| {
                    reqwest::StatusCode::from_u16(code)
                        .context(format!("Invalid HTTP status code: {}", code))
                })
                .and_then(|status_code| {
                    if !status_code.is_client_error() {
                        Err(anyhow::anyhow!(
                            "Status code {} is not a client error (4xx).",
                            status_code
                        ))
                    } else {
                        Ok(status_code)
                    }
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(allow_client_errors)
}
