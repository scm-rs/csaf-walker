use reqwest::Certificate;
use std::{fs::File, io::Read, path::Path};

#[allow(unused)]
pub fn add_cert<P: AsRef<Path>>(
    mut client: reqwest::ClientBuilder,
    cert: P,
) -> anyhow::Result<reqwest::ClientBuilder> {
    let cert = cert.as_ref();
    log::debug!("Adding root certificate: {cert:?}");

    let mut file = File::open(cert)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let pems = pem::parse_many(buf)?;
    let pems = pems
        .into_iter()
        .map(|pem| Certificate::from_pem(&pem::encode(&pem).into_bytes()).map_err(|err| err.into()))
        .collect::<anyhow::Result<Vec<_>>>()?;

    log::debug!("Found {} certificates", pems.len());

    for pem in pems {
        log::debug!("Adding root certificate: {pem:?}");
        client = client.add_root_certificate(pem);
    }

    Ok(client)
}
