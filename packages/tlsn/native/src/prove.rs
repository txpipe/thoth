// The tlsn@1 prover: fetch one HTTPS request through MPC-TLS with a notary, let the caller
// choose which bytes to reveal, commit exactly those, and build the presentation.
//
// It talks to its caller over stdin and stdout, one JSON object per line, because
// TLSNotary's hash commitments must be fixed before the notary signs, and the caller
// decides the reveal from the response:
//
//   stdin  → {"secretHeaders": {"Name": "value", …}}
//   stdout ← {"transcript": {"sent": "<hex>", "received": "<hex>"}}
//   stdin  → {"reveal": {"sent": [[start, end], …], "received": [[start, end], …]}}
//   stdout ← {"presentation": "<hex>"}
//
// Closing stdin instead of sending the reveal aborts without an attestation.

use std::{
    collections::BTreeMap,
    future::IntoFuture,
    io::{BufRead as _, Write as _},
    ops::Range,
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
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
    rangeset::set::RangeSet,
    transcript::TranscriptCommitConfig,
};
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
    /// The request body.
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Setup {
    /// Headers sent with the request whose values the caller keeps hidden.
    #[serde(default)]
    secret_headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Reveal {
    reveal: RevealRanges,
}

#[derive(Deserialize)]
struct RevealRanges {
    sent: Vec<[usize; 2]>,
    received: Vec<[usize; 2]>,
}

/// The largest line the caller may send.
const MAX_LINE_BYTES: u64 = 1 << 20;

/// Read one JSON line from the caller; `None` when it closed stdin.
fn read_line<T: for<'de> Deserialize<'de>>(input: &mut impl std::io::BufRead) -> Result<Option<T>> {
    let mut line = String::new();
    if std::io::Read::take(input, MAX_LINE_BYTES).read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_str(&line).context("the caller sent malformed JSON")?,
    ))
}

/// Check that ranges are sorted, disjoint, non-empty and inside `len`.
fn ranges_within(ranges: &[[usize; 2]], len: usize) -> Result<Vec<Range<usize>>> {
    let mut previous_end = 0;
    ranges
        .iter()
        .map(|&[start, end]| {
            if start < previous_end || end <= start || end > len {
                bail!("reveal ranges must be sorted, disjoint and inside the transcript");
            }
            previous_end = end;
            Ok(start..end)
        })
        .collect()
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
    let mut stdin = std::io::stdin().lock();
    let Some(setup) = read_line::<Setup>(&mut stdin)? else {
        bail!("the caller closed stdin before the setup line");
    };
    let secret: Vec<(String, String)> = setup.secret_headers.into_iter().collect();

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

    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .handshake(TokioIo::new(tls_connection.compat()))
        .await?;
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
        // Host and Connection come first, as the zkFetch witness requires: an attestor
        // reads the request only through that fixed prefix.
        .header("Host", host_header)
        .header("Connection", "close")
        // The attestor matches on the response text, which a compressed body would hide.
        .header("Accept-Encoding", "identity");
    for (name, value) in public.iter().chain(secret.iter()) {
        request = request.header(name.as_str(), value.as_str());
    }
    let body = Bytes::from(args.body.clone().unwrap_or_default());
    let response = sender.send_request(request.body(Full::new(body))?).await?;
    // Read the whole body so the transcript holds the complete response.
    response.into_body().collect().await?;

    let mut prover = prover_task.await??;

    // Hand the plaintext to the caller, and commit exactly the bytes it chooses to reveal.
    {
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(
            &mut stdout,
            &serde_json::json!({ "transcript": {
                "sent": hex::encode(prover.transcript().sent()),
                "received": hex::encode(prover.transcript().received()),
            }}),
        )?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    let Some(Reveal { reveal }) = read_line::<Reveal>(&mut stdin)? else {
        bail!("the caller aborted before choosing what to reveal");
    };
    let reveal_sent = RangeSet::from(ranges_within(
        &reveal.sent,
        prover.transcript().sent().len(),
    )?);
    let reveal_received = RangeSet::from(ranges_within(
        &reveal.received,
        prover.transcript().received().len(),
    )?);

    let mut commit = TranscriptCommitConfig::builder(prover.transcript());
    if !reveal_sent.is_empty() {
        commit.commit_sent(&reveal_sent)?;
    }
    if !reveal_received.is_empty() {
        commit.commit_recv(&reveal_received)?;
    }
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

    let mut proof = secrets.transcript_proof_builder();
    if !reveal_sent.is_empty() {
        proof.reveal_sent(&reveal_sent)?;
    }
    if !reveal_received.is_empty() {
        proof.reveal_recv(&reveal_received)?;
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
