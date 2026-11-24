// The thoth-tlsn tool: a TLSNotary notary, a prover that turns one HTTPS fetch
// into a presentation, and the presentation verifier a tlsn@1 attestor calls.

mod common;
mod notary;
mod prove;
mod verify;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// Parsed once per process, so the size of the largest variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Command {
    /// Run a notary that signs attestations carrying a Thoth claim context digest.
    Notary(notary::NotaryArgs),
    /// Print the public key of a notary signing key, as the attestor pins it.
    NotaryKey {
        /// The 32-byte secp256k1 signing key, as hex. Read from THOTH_TLSN_NOTARY_KEY when absent.
        #[arg(long, env = "THOTH_TLSN_NOTARY_KEY", hide_env_values = true)]
        signing_key: String,
    },
    /// Fetch one HTTPS request with a notary and print the presentation as JSON.
    Prove(prove::ProveArgs),
    /// Verify a presentation read from stdin and print what it authenticates as JSON.
    Verify {
        /// A DER root certificate to trust in place of the Mozilla roots, for test servers.
        #[arg(long)]
        root_cert: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Notary(args) => notary::run(args).await,
        Command::NotaryKey { signing_key } => {
            let key = common::notary_verifying_key(&signing_key)?;
            println!("{}", serde_json::to_string(&key)?);
            Ok(())
        }
        Command::Prove(args) => prove::run(args).await,
        Command::Verify { root_cert } => verify::run(root_cert).await,
    }
}
