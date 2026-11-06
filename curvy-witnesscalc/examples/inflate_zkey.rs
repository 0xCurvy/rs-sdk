//! Expand a compact zkey (`.czkey`) to the zkey it decodes to.
//!
//! ```text
//! cargo run --release -p curvy-witnesscalc --example inflate_zkey -- \
//!   <in.czkey> <compact-sha256> <out.zkey>
//! ```
//!
//! The compact file must match `<compact-sha256>`, and the decoded zkey must hash to the
//! digest its header names. Nothing is written unless both hold. The flake builds this to
//! produce the zkeys in `curvy-zk-artifacts`.

use anyhow::{Context, Result, bail};
use curvy_prover::compact_zkey::{self, DEFAULT_MAX_ZKEY_BYTES};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, compact_sha256, output] = args.as_slice() else {
        bail!("usage: inflate_zkey <in.czkey> <compact-sha256> <out.zkey>");
    };
    let compact = std::fs::read(input).with_context(|| format!("read {input}"))?;
    let actual = hex::encode(Sha256::digest(&compact));
    if actual != compact_sha256.to_ascii_lowercase() {
        bail!("{input}: sha256 {actual}, expected {compact_sha256}");
    }
    let zkey = compact_zkey::inflate(compact.as_slice(), DEFAULT_MAX_ZKEY_BYTES)
        .with_context(|| format!("inflate {input}"))?;
    std::fs::write(output, &zkey).with_context(|| format!("write {output}"))?;
    println!(
        "{output}: {} bytes, sha256 {}",
        zkey.len(),
        hex::encode(Sha256::digest(&zkey))
    );
    Ok(())
}
