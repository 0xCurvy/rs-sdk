//! Runs the strict PIX flow against the Blokli local-development stack.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let report = curvy_e2e::run().await?;
    print!("{}", report.summary());
    println!("rs-sdk PIX E2E: ALL PHASES PASSED");
    Ok(())
}
