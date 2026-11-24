// The tlsn@1 prover: fetch one HTTPS request through MPC-TLS with a notary, get its
// attestation with the claim context digest, and build the presentation an attestor checks.

use std::{future::IntoFuture, io::Read as _, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider, Extension,
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use url::Url;

use crate::common::{CLAIM_CONTEXT_BYTES, CLAIM_CONTEXT_EXTENSION_ID, crypto_provider, root_store};

/// The largest attestation the prover reads back from a notary.
const MAX_ATTESTATION_BYTES: u64 = 1 << 20;

#[derive(Args, Debug)]
pub struct ProveArgs {
    /// The notary's address, `host:port`.
    #[arg(long)]
    notary: String,
    /// The HTTPS URL to fetch.
    #[arg(long)]
    url: Url,
    /// The request method.
    #[arg(long, default_value = "GET")]
    method: String,
    /// A header revealed to the attestors, as `Name: value`. Repeatable.
    #[arg(long = "header")]
    headers: Vec<String>,
    /// A header whose value stays hidden from the attestors, as `Name: value`. Repeatable.
    /// Prefer `--secret-headers-stdin`: arguments are visible to other local users.
    #[arg(long = "secret-header")]
    secret_headers: Vec<String>,
    /// Read more hidden headers from stdin, as a JSON object of name to value.
    #[arg(long)]
    secret_headers_stdin: bool,
    /// The request body, revealed to the attestors.
    #[arg(long)]
    body: Option<String>,
    /// The 32-byte claim context digest the notary signs, as hex.
    #[arg(long)]
    claim_context: String,
    /// Connect to this `host:port` instead of the URL's host, keeping the URL's server name.
    #[arg(long)]
    connect: Option<String>,
    /// A DER root certificate to trust in place of the Mozilla roots, for test servers.
    #[arg(long)]
    root_cert: Option<PathBuf>,
    /// Bytes the prover may send; the MPC cost grows with it.
    #[arg(long, default_value_t = 1 << 12)]
    max_sent: usize,
    /// Bytes the prover may receive; the MPC cost grows with it.
    #[arg(long, default_value_t = 1 << 14)]
    max_recv: usize,
}

/// Split a `Name: value` header argument.
fn parse_header(raw: &str) -> Result<(String, String)> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("header {raw:?} is not `Name: value`"))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

/// Prove the request and print `{ "presentation": "<hex>" }`.
pub async fn run(args: ProveArgs) -> Result<()> {
    if args.url.scheme() != "https" {
        bail!("the url must be https");
    }
    let host = args
        .url
        .host_str()
        .ok_or_else(|| anyhow!("the url has no host"))?
        .to_string();
    let port = args.url.port_or_known_default().unwrap_or(443);
    let claim_context = hex::decode(&args.claim_context).context("claim context is not hex")?;
    if claim_context.len() != CLAIM_CONTEXT_BYTES {
        bail!("the claim context digest must be 32 bytes");
    }
    let public: Vec<_> = args
        .headers
        .iter()
        .map(|h| parse_header(h))
        .collect::<Result<_>>()?;
    let mut secret: Vec<_> = args
        .secret_headers
        .iter()
        .map(|h| parse_header(h))
        .collect::<Result<_>>()?;
    if args.secret_headers_stdin {
        let mut raw = String::new();
        std::io::stdin().take(1 << 16).read_to_string(&mut raw)?;
        let headers: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&raw).context("stdin is not a JSON object of headers")?;
        secret.extend(headers);
    }
    let secret_names: Vec<String> = secret
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();

    let notary_socket = TcpStream::connect(&args.notary)
        .await
        .with_context(|| format!("cannot reach notary {}", args.notary))?;
    notary_socket.set_nodelay(true)?;
    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(args.max_sent)
                .max_recv_data(args.max_recv)
                .build()?,
        )
        .await?;

    let target = args
        .connect
        .clone()
        .unwrap_or_else(|| format!("{host}:{port}"));
    let server_socket = TcpStream::connect(&target)
        .await
        .with_context(|| format!("cannot reach server {target}"))?;
    server_socket.set_nodelay(true)?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(host.clone().try_into()?))
            .root_store(root_store(args.root_cert.as_deref())?)
            .build()?,
        server_socket.compat(),
    )?;
    let prover_task = tokio::spawn(prover.into_future());

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat())).await?;
    tokio::spawn(connection);

    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path = match args.url.query() {
        Some(query) => format!("{}?{query}", args.url.path()),
        None => args.url.path().to_string(),
    };
    let mut request = Request::builder()
        .method(args.method.as_str())
        .uri(path)
        .header("Host", host_header)
        // TLSNotary cannot read a compressed response, and the attestor parses the body.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close");
    for (name, value) in public.iter().chain(secret.iter()) {
        request = request.header(name.as_str(), value.as_str());
    }
    let body = Bytes::from(args.body.clone().unwrap_or_default());
    let response = sender.send_request(request.body(Full::new(body))?).await?;
    // Read the whole body so the transcript holds the complete response.
    response.into_body().collect().await?;

    let mut prover = prover_task.await??;
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let mut commit = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut commit, &transcript)?;
    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(commit.build()?);
    request_config.extension(Extension {
        id: CLAIM_CONTEXT_EXTENSION_ID.to_vec(),
        value: claim_context,
    });
    let request_config = request_config.build()?;

    let mut prove_config = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_config.transcript_commit(config.clone());
    }
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config.build()?).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(host.clone().try_into()?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .ok_or_else(|| anyhow!("the server sent no certificate chain"))?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .ok_or_else(|| anyhow!("the server sent no signature"))?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let provider = crypto_provider(args.root_cert.as_deref())?;
    let (attestation_request, secrets) = builder.build(&provider)?;

    handle.close();
    let mut socket = driver_task.await??;
    socket
        .write_all(&bincode::serialize(&attestation_request)?)
        .await?;
    socket.close().await?;
    let mut attestation_bytes = Vec::new();
    (&mut socket)
        .take(MAX_ATTESTATION_BYTES)
        .read_to_end(&mut attestation_bytes)
        .await?;
    let attestation: Attestation =
        bincode::deserialize(&attestation_bytes).context("the notary returned no attestation")?;
    attestation_request.validate(&attestation, &CryptoProvider::default())?;

    // Reveal the whole request except the values of the secret headers, and the whole
    // response: a tlsn@1 attestor parses the response itself and refuses hidden bytes in it.
    let transcript = HttpTranscript::parse(secrets.transcript())?;
    let mut proof = secrets.transcript_proof_builder();
    for request in &transcript.requests {
        proof.reveal_sent(request.without_data())?;
        proof.reveal_sent(&request.request.target)?;
        for header in &request.headers {
            let name = header.name.as_str().to_ascii_lowercase();
            if secret_names.contains(&name) {
                proof.reveal_sent(header.without_value())?;
            } else {
                proof.reveal_sent(header)?;
            }
        }
        if let Some(body) = &request.body {
            proof.reveal_sent(body)?;
        }
    }
    for response in &transcript.responses {
        proof.reveal_recv(response)?;
    }

    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(proof.build()?);
    let presentation: Presentation = presentation.build()?;

    println!(
        "{}",
        serde_json::json!({ "presentation": hex::encode(bincode::serialize(&presentation)?) })
    );
    Ok(())
}
