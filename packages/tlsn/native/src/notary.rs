// A TLSNotary notary for tlsn@1: it runs MPC-TLS with a prover over TCP and signs
// an attestation that may carry exactly one extension, the claim context digest.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, InvalidExtension,
        request::Request as AttestationRequest, signing::Signer,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, warn};

use crate::common::{
    CLAIM_CONTEXT_BYTES, CLAIM_CONTEXT_EXTENSION_ID, NotaryKeyJson, notary_signer, root_store,
};

/// The largest attestation request the notary reads, so a client cannot exhaust its memory.
const MAX_REQUEST_BYTES: u64 = 1 << 20;

#[derive(Args, Debug)]
pub struct NotaryArgs {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:7047")]
    listen: SocketAddr,
    /// The 32-byte secp256k1 signing key, as hex. Read from THOTH_TLSN_NOTARY_KEY when absent.
    #[arg(long, env = "THOTH_TLSN_NOTARY_KEY", hide_env_values = true)]
    signing_key: String,
    /// A DER root certificate to trust in place of the Mozilla roots, for test servers.
    #[arg(long)]
    root_cert: Option<PathBuf>,
}

/// Serve provers until the process is stopped.
pub async fn run(args: NotaryArgs) -> Result<()> {
    let signer = notary_signer(&args.signing_key)?;
    let public = NotaryKeyJson::from(&signer.verifying_key());
    let roots = Arc::new(root_store(args.root_cert.as_deref())?);
    let signing_key = Arc::new(args.signing_key);

    let listener = TcpListener::bind(args.listen).await?;
    // The address and key go to stdout as one JSON line, so a test harness can wait for them.
    println!(
        "{}",
        serde_json::json!({ "listening": listener.local_addr()?.to_string(), "notaryKey": public })
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let roots = roots.clone();
        let signing_key = signing_key.clone();
        tokio::spawn(async move {
            match notarize(socket, &roots, &signing_key).await {
                Ok(()) => info!(%peer, "attestation signed"),
                Err(err) => warn!(%peer, "notarization failed: {err:#}"),
            }
        });
    }
}

/// Accept only the claim context extension, at most once and exactly 32 bytes long.
fn validate_extensions(
    extensions: &[tlsn::attestation::Extension],
) -> Result<(), InvalidExtension> {
    if extensions.len() > 1 {
        return Err(InvalidExtension::new("at most one extension is accepted"));
    }
    for extension in extensions {
        if extension.id != CLAIM_CONTEXT_EXTENSION_ID {
            return Err(InvalidExtension::new(
                "only the thoth.claim-context extension is accepted",
            ));
        }
        if extension.value.len() != CLAIM_CONTEXT_BYTES {
            return Err(InvalidExtension::new(
                "the claim context digest must be 32 bytes",
            ));
        }
    }
    Ok(())
}

/// Run one notarization: MPC-TLS with the prover, then sign its attestation request.
async fn notarize(socket: TcpStream, roots: &RootCertStore, signing_key: &str) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(roots.clone())
        .build()?;
    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            verifier
                .reject(Some("this notary runs MPC-TLS only"))
                .await?;
            bail!("the prover asked for proxy mode");
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let application_data_len = |records: &[tlsn::transcript::Record]| -> usize {
        records
            .iter()
            .filter(|record| matches!(record.typ, ContentType::ApplicationData))
            .map(|record| record.ciphertext.len())
            .sum()
    };
    let sent_len = application_data_len(tls_transcript.sent());
    let recv_len = application_data_len(tls_transcript.recv());

    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    (&mut socket)
        .take(MAX_REQUEST_BYTES)
        .read_to_end(&mut request_bytes)
        .await?;
    let request: AttestationRequest =
        bincode::deserialize(&request_bytes).context("malformed attestation request")?;

    let mut provider = CryptoProvider::default();
    provider
        .signer
        .set_signer(Box::new(notary_signer(signing_key)?));

    let mut config = AttestationConfig::builder();
    config
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()))
        .extension_validator(validate_extensions);
    let config = config.build()?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        return Err(anyhow!("unsupported certificate binding version"));
    };
    let mut builder = Attestation::builder(&config).accept_request(request)?;
    builder
        // The connection time is the notary's own clock; tlsn@1 reads it as the observation time.
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider)?;

    socket.write_all(&bincode::serialize(&attestation)?).await?;
    socket.close().await?;
    Ok(())
}
