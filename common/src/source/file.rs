use crate::retrieve::{RetrievedDigest, parse_digest_file};
use anyhow::anyhow;
use bytes::Bytes;
use digest::Digest;
use futures_util::try_join;
use sha2::{Sha256, Sha512};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use url::Url;

pub async fn read_optional(path: impl AsRef<Path>) -> Result<Option<String>, anyhow::Error> {
    match tokio::fs::read_to_string(path).await {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn to_path(url: &Url) -> Result<PathBuf, anyhow::Error> {
    url.to_file_path()
        .map_err(|()| anyhow!("Failed to convert URL to path: {url}"))
}

/// Read the signature file and digests
///
/// The expected locations are:
/// * `{base}.asc`
/// * `{base}.sha256`
/// * `{base}.sha512`
pub async fn read_sig_and_digests(
    path: &Path,
    data: &Bytes,
) -> anyhow::Result<(
    Option<String>,
    Option<RetrievedDigest<Sha256>>,
    Option<RetrievedDigest<Sha512>>,
)> {
    let (signature, sha256, sha512) = try_join!(
        read_optional(format!("{}.asc", path.display())),
        read_optional(format!("{}.sha256", path.display())),
        read_optional(format!("{}.sha512", path.display())),
    )?;

    let sha256 = sha256
        .and_then(|expected| parse_digest_file(&expected))
        .map(|expected| {
            let mut actual = Sha256::new();
            actual.update(data);
            RetrievedDigest::<Sha256> {
                expected,
                actual: actual.finalize(),
            }
        });

    let sha512 = sha512
        .and_then(|expected| parse_digest_file(&expected))
        .map(|expected| {
            let mut actual = Sha512::new();
            actual.update(data);
            RetrievedDigest::<Sha512> {
                expected,
                actual: actual.finalize(),
            }
        });

    Ok((signature, sha256, sha512))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex::Hex;
    use rstest::rstest;

    const DOC: &[u8] = b"test data";

    /// Write the document and its digest files, using `format` to render the digest file content.
    async fn read_with(
        format: impl Fn(String) -> String,
    ) -> (
        Option<RetrievedDigest<Sha256>>,
        Option<RetrievedDigest<Sha512>>,
    ) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("doc.json");

        tokio::fs::write(&path, DOC).await.expect("write doc");
        tokio::fs::write(
            format!("{}.sha256", path.display()),
            format(Hex(&Sha256::digest(DOC)).to_lower()),
        )
        .await
        .expect("write sha256");
        tokio::fs::write(
            format!("{}.sha512", path.display()),
            format(Hex(&Sha512::digest(DOC)).to_lower()),
        )
        .await
        .expect("write sha512");

        let (_, sha256, sha512) = read_sig_and_digests(&path, &Bytes::from_static(DOC))
            .await
            .expect("read digests");

        (sha256, sha512)
    }

    #[rstest]
    #[case::bare(|h| h)]
    #[case::lf(|h| format!("{h}\n"))]
    #[case::crlf_uppercase(|h: String| format!("{}\r\n", h.to_uppercase()))]
    #[case::space_name(|h| format!("{h}  doc.json\n"))]
    #[case::tab_name(|h| format!("{h}\tdoc.json"))]
    #[tokio::test]
    async fn digest_file_formats(#[case] format: fn(String) -> String) {
        let (sha256, sha512) = read_with(format).await;

        assert!(sha256.expect("sha256 digest").validate().is_ok());
        assert!(sha512.expect("sha512 digest").validate().is_ok());
    }

    #[rstest]
    #[case::empty(|_| String::new())]
    #[case::only_whitespace(|_| " \r\n".to_string())]
    #[tokio::test]
    async fn empty_digest_files(#[case] format: fn(String) -> String) {
        let (sha256, sha512) = read_with(format).await;

        assert!(sha256.is_none());
        assert!(sha512.is_none());
    }
}
