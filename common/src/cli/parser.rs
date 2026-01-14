use anyhow::Context;
use reqwest::StatusCode;
use std::{collections::HashSet, fmt::Display};

/// Parses the allowed client errors from the command line arguments.
pub fn parse_allow_client_errors(
    allow_missing: bool,
    allow_client_errors: impl IntoIterator<Item = impl AsRef<str> + Display>,
) -> anyhow::Result<HashSet<StatusCode>> {
    let mut allow_client_errors: HashSet<StatusCode> = allow_client_errors
        .into_iter()
        .map(|s| {
            s.as_ref()
                .parse::<u16>()
                .context(format!("Failed to parse '{s}' as an integer"))
                .and_then(|code| {
                    StatusCode::from_u16(code)
                        .with_context(|| format!("Invalid HTTP status code: {code}"))
                })
                .and_then(|status_code| {
                    if !status_code.is_client_error() {
                        Err(anyhow::anyhow!(
                            "Status code {status_code} is not a client error (4xx)"
                        ))
                    } else {
                        Ok(status_code)
                    }
                })
        })
        .collect::<Result<_, _>>()?;

    if allow_missing {
        allow_client_errors.insert(StatusCode::NOT_FOUND);
    }

    Ok(allow_client_errors)
}
