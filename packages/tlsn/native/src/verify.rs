// The presentation verifier a tlsn@1 attestor calls: it checks the notary's signature,
// the server identity and the transcript proof, and prints what they authenticate.
// It does not decide whether to trust the notary; the attestor pins its key.

use std::{io::Read as _, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tlsn::attestation::presentation::{Presentation, PresentationOutput};

use crate::common::{NotaryKeyJson, crypto_provider};

/// The largest presentation the verifier reads from stdin.
const MAX_PRESENTATION_HEX: u64 = 4 << 20;

#[derive(Deserialize)]
struct Input {
    presentation: String,
}

/// One direction of the transcript: its full length, the bytes, and which of them are revealed.
#[derive(Serialize)]
struct Direction {
    length: usize,
    /// Every byte as lowercase hex; a byte outside `revealed` is `00` and carries no data.
    data: String,
    /// Revealed byte ranges, `[start, end)`, sorted and disjoint.
    revealed: Vec<[usize; 2]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    notary_key: NotaryKeyJson,
    /// The DNS name the server's certificate was verified for.
    server_name: String,
    /// When the notary saw the server's hello, Unix seconds, by the notary's clock.
    time: u64,
    sent: Direction,
    received: Direction,
    extensions: Vec<ExtensionJson>,
}

#[derive(Serialize)]
struct ExtensionJson {
    id: String,
    value: String,
}

/// Read `{ "presentation": "<hex>" }` from stdin, verify it, and print the result as JSON.
pub async fn run(root_cert: Option<PathBuf>) -> Result<()> {
    let mut raw = String::new();
    std::io::stdin()
        .take(MAX_PRESENTATION_HEX)
        .read_to_string(&mut raw)
        .context("cannot read stdin")?;
    let input: Input = serde_json::from_str(&raw).context("stdin is not a presentation")?;
    let bytes = hex::decode(input.presentation.trim()).context("the presentation is not hex")?;
    let presentation: Presentation =
        bincode::deserialize(&bytes).context("the presentation does not decode")?;

    let notary_key = NotaryKeyJson::from(presentation.verifying_key());
    let provider = crypto_provider(root_cert.as_deref())?;
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        extensions,
        ..
    } = presentation
        .verify(&provider)
        .map_err(|err| anyhow!("the presentation does not verify: {err}"))?;

    let Some(server_name) = server_name else {
        bail!("the presentation carries no server identity proof");
    };
    let Some(transcript) = transcript else {
        bail!("the presentation carries no transcript proof");
    };
    let sent = transcript.sent_unsafe(transcript.len_sent())?;
    let received = transcript.received_unsafe(transcript.len_received())?;
    let ranges = |set: &tlsn::rangeset::set::RangeSet<usize>| -> Vec<[usize; 2]> {
        set.iter().map(|range| [range.start, range.end]).collect()
    };

    let output = Output {
        notary_key,
        server_name: server_name.to_string(),
        time: connection_info.time,
        sent: Direction {
            length: sent.len(),
            data: hex::encode(&sent),
            revealed: ranges(transcript.sent_authed()),
        },
        received: Direction {
            length: received.len(),
            data: hex::encode(&received),
            revealed: ranges(transcript.received_authed()),
        },
        extensions: extensions
            .iter()
            .map(|extension| ExtensionJson {
                id: hex::encode(&extension.id),
                value: hex::encode(&extension.value),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
