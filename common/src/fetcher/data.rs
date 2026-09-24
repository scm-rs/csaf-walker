use bytes::Bytes;
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use std::future::Future;
use std::ops::{Deref, DerefMut};

/// Data which can be extracted from a [`Response`].
pub trait Data: Sized {
    fn from_response(
        response: Response,
    ) -> impl Future<Output = Result<Self, reqwest::Error>> + Send;
}

/// String data
impl Data for String {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.text().await
    }
}

/// BLOB data
impl Data for Bytes {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.bytes().await
    }
}

/// A new-type wrapping [`String`].
pub struct Text(pub String);

impl Data for Text {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.text().await.map(Self)
    }
}

impl Text {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for Text {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Text {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// JSON based data.
pub struct Json<D>(pub D)
where
    D: DeserializeOwned;

impl<D> Data for Json<D>
where
    D: DeserializeOwned,
{
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.json().await.map(Self)
    }
}

impl<D: DeserializeOwned> Json<D> {
    #[inline]
    pub fn into_inner(self) -> D {
        self.0
    }
}

impl<D: DeserializeOwned> Deref for Json<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D: DeserializeOwned> DerefMut for Json<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<D: Data> Data for Option<D> {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(D::from_response(response).await?))
    }
}

/// Like `Option<D>`, but treats any 4xx client error as `None`.
///
/// Use this for auxiliary resources (signatures, digests) where the server may
/// return 403 or another client error instead of 404 when the file does not
/// exist or is not accessible.
pub struct Lenient<D>(pub Option<D>);

impl<D> Lenient<D> {
    pub fn into_inner(self) -> Option<D> {
        self.0
    }
}

impl<D> From<Lenient<D>> for Option<D> {
    fn from(lenient: Lenient<D>) -> Self {
        lenient.0
    }
}

impl<D> Deref for Lenient<D> {
    type Target = Option<D>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D> DerefMut for Lenient<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<D: Data> Data for Lenient<D> {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        if response.status().is_client_error() {
            return Ok(Lenient(None));
        }

        Ok(Lenient(Some(D::from_response(response).await?)))
    }
}
