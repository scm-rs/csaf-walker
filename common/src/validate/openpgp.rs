//! OpenPGP validation
use crate::{utils::openpgp::PublicKey, validate::ValidationOptions};
use anyhow::bail;
use sequoia_openpgp::{
    Cert, KeyHandle, Packet,
    cert::prelude::ValidErasedKeyAmalgamation,
    packet::{Signature, key::PublicParts},
    parse::{
        Parse,
        stream::{DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper},
    },
    policy::{HashAlgoSecurity, Policy, StandardPolicy},
    types::{AEADAlgorithm, SymmetricAlgorithm},
};
use std::fmt::Debug;

/// A verify helper for `PublicKey`.
pub struct Helper<'a> {
    pub keys: &'a [PublicKey],
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(self.keys.iter().flat_map(|k| k.certs.clone()).collect())
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        let mut good = false;

        for (i, layer) in structure.into_iter().enumerate() {
            log::trace!("Message ({i}): {layer:?}");

            match (i, layer) {
                (0, MessageLayer::SignatureGroup { results }) => match results.into_iter().next() {
                    Some(Ok(_)) => good = true,
                    Some(Err(err)) => {
                        return Err(sequoia_openpgp::Error::from(err).into());
                    }
                    None => {
                        bail!("No signature");
                    }
                },
                _ => {
                    bail!("Unexpected message structure");
                }
            }
        }

        if !good {
            bail!("Signature verification failed")
        }

        Ok(())
    }
}

/// A wrapper policy, logging the outcome of the package call on debug level.
#[derive(Debug)]
pub struct LoggingPolicy<'a>(pub StandardPolicy<'a>);

impl Policy for LoggingPolicy<'_> {
    fn signature(&self, sig: &Signature, sec: HashAlgoSecurity) -> sequoia_openpgp::Result<()> {
        self.0.signature(sig, sec)
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<PublicParts>) -> sequoia_openpgp::Result<()> {
        self.0.key(ka)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm) -> sequoia_openpgp::Result<()> {
        self.0.symmetric_algorithm(algo)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm) -> sequoia_openpgp::Result<()> {
        self.0.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet) -> sequoia_openpgp::Result<()> {
        self.0.packet(packet).inspect_err(|_| {
            log::debug!(
                "Failed to validate packet - tag: {tag:?}, version = {version:?}",
                tag = packet.tag(),
                version = packet.version()
            );
        })
    }
}

/// Validate a PGP signature
pub fn validate_signature(
    options: &ValidationOptions,
    keys: &[PublicKey],
    signature: &str,
    data: impl AsRef<[u8]>,
) -> Result<(), anyhow::Error> {
    // TODO: we could move this into the context and re-use
    let policy = match options.validation_date {
        Some(time) => StandardPolicy::at(time),
        None => StandardPolicy::new(),
    };
    let policy = LoggingPolicy(policy);
    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature)?.with_policy(
        &policy,
        None,
        Helper { keys },
    )?;

    verifier.verify_bytes(data)?;

    Ok(())
}
