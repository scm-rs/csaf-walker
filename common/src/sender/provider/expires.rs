use jiff::Timestamp;

/// Check if something expired or expires soon.
pub trait Expires {
    /// Check if the resource expires before the duration elapsed.
    fn expires_before(&self, duration: time::Duration) -> bool;
}

impl Expires for openid::TemporalBearerGuard {
    fn expires_before(&self, duration: time::Duration) -> bool {
        match self.expires_at() {
            Some(expires) => {
                // OpenID exposes a chrono timestamp, but caps token lifetimes at 100 years.
                let expires = Timestamp::try_from(std::time::SystemTime::from(expires))
                    .expect("OpenID token expiration must fit in a Jiff timestamp");
                expires.duration_since(Timestamp::now()).as_secs() <= duration.whole_seconds()
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::no_expiration(None, 60, false)]
    #[case::expired(Some(0), 60, true)]
    #[case::valid(Some(3600), 60, false)]
    #[case::expires_soon(Some(3600), 7200, true)]
    #[case::maximum_lifetime(Some(u64::MAX), 60, false)]
    fn token_expiration(
        #[case] expires_in: Option<u64>,
        #[case] refresh_before: i64,
        #[case] expected: bool,
    ) {
        let mut bearer = json!({"access_token": "test", "token_type": "Bearer"});
        if let Some(expires_in) = expires_in {
            bearer["expires_in"] = expires_in.into();
        }
        let bearer: openid::Bearer = serde_json::from_value(bearer).unwrap();
        let token = openid::TemporalBearerGuard::from(bearer);
        assert_eq!(
            token.expires_before(time::Duration::seconds(refresh_before)),
            expected
        );
    }
}
