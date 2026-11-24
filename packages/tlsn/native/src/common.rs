// Shared pieces: the claim context extension, the notary key and root stores.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tlsn::{
    attestation::{
        CryptoProvider,
        signing::{Secp256k1Signer, Signer, VerifyingKey},
    },
    verifier::ServerCertVerifier,
    webpki::{CertificateDer, RootCertStore},
};

/// The extension id under which a prover asks the notary to sign the claim context digest.
pub const CLAIM_CONTEXT_EXTENSION_ID: &[u8] = b"thoth.claim-context";

/// Byte length of the claim context digest.
pub const CLAIM_CONTEXT_BYTES: usize = 32;

/// A notary's public key as the attestor pins it.
#[derive(Debug, Serialize)]
pub struct NotaryKeyJson {
    /// The key algorithm, as TLSNotary names it (`k256`, `p256`).
    pub alg: String,
    /// The key bytes, as lowercase hex.
    pub key: String,
}

impl From<&VerifyingKey> for NotaryKeyJson {
    fn from(key: &VerifyingKey) -> Self {
        Self {
            alg: key.alg.to_string(),
            key: hex::encode(&key.data),
        }
    }
}

/// Build the notary's secp256k1 signer from a 32-byte hex key.
pub fn notary_signer(signing_key_hex: &str) -> Result<Secp256k1Signer> {
    let bytes = hex::decode(signing_key_hex.trim().trim_start_matches("0x"))
        .context("the notary signing key is not hex")?;
    if bytes.len() != 32 {
        bail!(
            "the notary signing key must be 32 bytes, got {}",
            bytes.len()
        );
    }
    Secp256k1Signer::new(&bytes).map_err(|err| anyhow::anyhow!("invalid notary signing key: {err}"))
}

/// The public key a notary signing key signs under.
pub fn notary_verifying_key(signing_key_hex: &str) -> Result<NotaryKeyJson> {
    Ok(NotaryKeyJson::from(
        &notary_signer(signing_key_hex)?.verifying_key(),
    ))
}

/// The roots the server certificate must chain to: one DER file, or the Mozilla roots.
pub fn root_store(root_cert: Option<&Path>) -> Result<RootCertStore> {
    match root_cert {
        Some(path) => {
            let der = std::fs::read(path)
                .with_context(|| format!("cannot read root certificate {}", path.display()))?;
            Ok(RootCertStore {
                roots: vec![CertificateDer(der)],
            })
        }
        None => Ok(RootCertStore::mozilla()),
    }
}

/// A crypto provider whose certificate verifier trusts `root_cert`, or the Mozilla roots.
pub fn crypto_provider(root_cert: Option<&Path>) -> Result<CryptoProvider> {
    Ok(match root_cert {
        Some(path) => CryptoProvider {
            cert: ServerCertVerifier::new(&root_store(Some(path))?)?,
            ..Default::default()
        },
        None => CryptoProvider::default(),
    })
}
