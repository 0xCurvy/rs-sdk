//! Runs the acceptance flow against a local Blokli stack.

use anyhow::{Result, bail};

const USAGE: &str = "\
curvy-e2e - acceptance flow against a local Blokli stack

  curvy-e2e              run all nine phases
  curvy-e2e --preflight  check artifacts, proving keys and Blokli, then exit

Environment:
  BLOKLI_URL          default http://127.0.0.1:8080
  CURVY_ADDRESSES     Blokli's curvy_deployed_addresses.json
  CURVY_ZK_KEYS_DIR   the zk-keys/v2 tree
  CURVY_E2E_SALT      u64, to replay a specific run against a fresh chain

`--preflight` validates dependencies without submitting transactions.";

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        None => {
            let report = curvy_e2e::run().await?;
            print!("{}", report.summary());
            println!("rs-sdk E2E: ALL PHASES PASSED");
        }
        Some("--preflight") => {
            let preflight = curvy_e2e::preflight().await?;
            print!("{}", preflight.summary());
            println!("preflight: OK");
        }
        Some("-h" | "--help") => println!("{USAGE}"),
        Some(other) => bail!("unknown argument {other:?}\n\n{USAGE}"),
    }
    Ok(())
}
