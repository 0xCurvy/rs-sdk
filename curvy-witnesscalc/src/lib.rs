//! Witness generation and Groth16 proving for the Curvy circuits.
//!
//! Every circuit needs two artifacts at runtime: a `SIGNET01` witness graph and a Groth16
//! proving key. Both are resolved the same way - a circuit-specific environment variable
//! wins, otherwise the file is looked up flat under [`ARTIFACTS_DIR_ENV`] - and both are
//! authenticated by SHA-256 before use. The artifacts ship with the SDK's GitHub releases,
//! not with the crate. Only the `bundled-graphs` feature, meant for this repository's own
//! tests and acceptance flow, falls back to the graphs checked into the source tree.

use anyhow::{Context, Result, bail};
use ark_bn254::Fr;
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub mod pending;
pub mod pix;

/// Optional newline-delimited JSON destination for proof timing records.
///
/// This is deliberately separate from `tracing`: acceptance tests run proofs on blocking
/// worker threads and must retain measurements even when a subscriber filter changes or the
/// process is terminated immediately after the protocol completes.
pub const PROOF_TIMINGS_PATH_ENV: &str = "CURVY_PROOF_TIMINGS_PATH";

/// Directory holding the witness graphs and proving keys, flat, one file per circuit.
///
/// Circuit-specific overrides (`CURVY_<CIRCUIT>_GRAPH`, `CURVY_<CIRCUIT>_ZKEY`) take
/// precedence over it.
pub const ARTIFACTS_DIR_ENV: &str = "CURVY_ZK_KEYS_DIR";

fn artifacts_dir() -> Option<PathBuf> {
    std::env::var_os(ARTIFACTS_DIR_ENV).map(PathBuf::from)
}

static PROOF_TIMING_WRITER: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(serde::Serialize)]
struct ProofTimingRecord<'a> {
    schema_version: u8,
    unix_time_ms: u128,
    circuit: &'a str,
    graph_load_ms: u64,
    prover_load_ms: u64,
    witness_ms: u64,
    groth16_ms: u64,
    total_ms: u64,
}

fn append_proof_timing(path: &Path, record: &ProofTimingRecord<'_>) -> Result<()> {
    let _guard = PROOF_TIMING_WRITER
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("Curvy proof timing writer lock was poisoned"))?;
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open Curvy proof timing sink {}", path.display()))?;
    serde_json::to_writer(&mut output, record).context("encode Curvy proof timing record")?;
    output
        .write_all(b"\n")
        .context("terminate Curvy proof timing record")?;
    output.flush().context("flush Curvy proof timing record")?;
    Ok(())
}

fn record_proof_timing(record: &ProofTimingRecord<'_>) {
    let Some(path) = std::env::var_os(PROOF_TIMINGS_PATH_ENV) else {
        return;
    };
    if let Err(error) = append_proof_timing(Path::new(&path), record) {
        tracing::warn!(
            path = %Path::new(&path).display(),
            %error,
            "failed to persist Curvy proof timing"
        );
    }
}

/// Produces a BN254 witness assignment from circuit input JSON.
pub trait WitnessCalculator {
    fn calculate(&self, input_json: &str) -> Result<Vec<Fr>>;
}

/// A parsed, reusable `SIGNET01` evaluation graph.
pub struct GraphWitnessCalculator {
    graph: WitnessGraph,
}

impl GraphWitnessCalculator {
    /// Authenticate and parse a graph.
    pub fn from_graph_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        Ok(Self {
            graph: WitnessGraph::from_bytes(bytes, expected_sha256)?,
        })
    }

    /// Number of signals produced by this graph.
    pub fn assignment_size(&self) -> usize {
        self.graph.assignment_size()
    }
}

impl WitnessCalculator for GraphWitnessCalculator {
    fn calculate(&self, input_json: &str) -> Result<Vec<Fr>> {
        Ok(self.graph.calculate_json(input_json)?)
    }
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Pinned graph, proving key, and public-input count.
pub struct Circuit {
    pub key: &'static str,
    pub label: &'static str,
    graph_env: &'static str,
    graph_file: &'static str,
    graph_sha256: &'static str,
    zkey_env: &'static str,
    zkey_file: &'static str,
    zkey_sha256: &'static str,
    pub num_public: usize,
}

/// The graphs checked into this repository, for its own tests and acceptance flow.
#[cfg(feature = "bundled-graphs")]
fn bundled_graphs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts/signet")
}

impl Circuit {
    pub fn withdrawal() -> Self {
        Circuit {
            key: "withdrawal",
            label: "withdrawal(2,30)",
            graph_env: "CURVY_WITHDRAWAL_GRAPH",
            graph_file: "withdrawal-2-30.signet.zst",
            graph_sha256: "04b2fa84394548a971c757c61280b81fb7699a367eeb45834201675f8a0aad74",
            zkey_env: "CURVY_WITHDRAWAL_ZKEY",
            zkey_file: "verifySingleWithdrawalNoHashing_2_30_0001.zkey",
            zkey_sha256: "c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716",
            num_public: 6,
        }
    }

    pub fn aggregation() -> Self {
        Circuit {
            key: "aggregation",
            label: "aggregation(2,3,30,6)",
            graph_env: "CURVY_AGGREGATION_GRAPH",
            graph_file: "aggregation-2-3-30.signet.zst",
            graph_sha256: "8c6eb16f41cc147fca8809804c0f0743d463aeba2ee45a02e7b32b6a27904386",
            zkey_env: "CURVY_AGGREGATION_ZKEY",
            zkey_file: "verifySingleAggregationNoHashing_2_3_30_0001.zkey",
            zkey_sha256: "88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6",
            num_public: 31,
        }
    }

    pub fn pix_aggregation() -> Self {
        Circuit {
            key: "pix-aggregation",
            label: "pix-aggregation(2,9,30,6)",
            graph_env: "CURVY_PIX_AGGREGATION_GRAPH",
            graph_file: "pix-aggregation-2-9-30.signet.zst",
            graph_sha256: "b974028ba40afdc067524819d61bdd9172a5e56369cfc05a75ba5d469c379c3a",
            zkey_env: "CURVY_PIX_AGGREGATION_ZKEY",
            zkey_file: "verifyPixAggregation_2_9_30_evaluation.zkey",
            zkey_sha256: "b4fced8a3c183d25a13a24c9ee7234ec96b77f87f688992ee07144f23ace6750",
            num_public: 67,
        }
    }

    pub fn pix_withdrawal() -> Self {
        Circuit {
            key: "pix-withdrawal",
            label: "pix-withdrawal(10,30)",
            graph_env: "CURVY_PIX_WITHDRAWAL_GRAPH",
            graph_file: "pix-withdrawal-10-30.signet.zst",
            graph_sha256: "90d301a189ceea1a7574f410bd94e53e9da0da0e75d8bfb99d47c42295fdfa56",
            zkey_env: "CURVY_PIX_WITHDRAWAL_ZKEY",
            zkey_file: "verifyPixMultiOwnerWithdrawal_10_30_evaluation.zkey",
            zkey_sha256: "e18f0fdd40aa2643c31c3a02ef0a508b5c7580a436abcae88e364ee86be6a95b",
            num_public: 14,
        }
    }

    pub fn pending() -> Self {
        Circuit {
            key: "pending",
            label: "pending-notes-commitment(5,30)",
            graph_env: "CURVY_PENDING_GRAPH",
            graph_file: "pending-5-30.signet.zst",
            graph_sha256: "69fa449825732a0958ccd0689ad361d9e8df1223231d8b71932d0efc4a07d8f0",
            zkey_env: "CURVY_PENDING_ZKEY",
            zkey_file: "verifyPendingNotesCommitment_5_30_0001.zkey",
            zkey_sha256: "efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847",
            num_public: 1,
        }
    }

    /// Circuits used by the acceptance flow, in execution order.
    pub fn pix_flow() -> [Self; 3] {
        [
            Circuit::pending(),
            Circuit::pix_aggregation(),
            Circuit::pix_withdrawal(),
        ]
    }

    /// File name of the witness graph under [`ARTIFACTS_DIR_ENV`].
    pub fn graph_file(&self) -> &'static str {
        self.graph_file
    }

    /// File name of the proving key under [`ARTIFACTS_DIR_ENV`].
    pub fn zkey_file(&self) -> &'static str {
        self.zkey_file
    }

    /// Resolved graph path: the circuit's own variable, else the file under
    /// [`ARTIFACTS_DIR_ENV`].
    ///
    /// With the `bundled-graphs` feature the repository's copy is the last resort, also
    /// when the artifacts directory is set but does not hold the graph.
    pub fn graph_path(&self) -> Result<PathBuf> {
        if let Some(path) = std::env::var_os(self.graph_env) {
            return Ok(PathBuf::from(path));
        }
        if let Some(root) = artifacts_dir() {
            let path = root.join(self.graph_file);
            #[cfg(feature = "bundled-graphs")]
            if !path.is_file() {
                return Ok(bundled_graphs().join(self.graph_file));
            }
            return Ok(path);
        }
        #[cfg(feature = "bundled-graphs")]
        {
            Ok(bundled_graphs().join(self.graph_file))
        }
        #[cfg(not(feature = "bundled-graphs"))]
        {
            bail!(
                "{}: witness graph location is not configured; set {} or {ARTIFACTS_DIR_ENV}",
                self.key,
                self.graph_env
            )
        }
    }

    /// Pinned graph digest.
    pub fn graph_sha256(&self) -> &'static str {
        self.graph_sha256
    }
    /// Resolved proving-key path, including environment overrides.
    pub fn zkey_path(&self) -> Result<PathBuf> {
        if let Some(path) = std::env::var_os(self.zkey_env) {
            return Ok(PathBuf::from(path));
        }
        let root = artifacts_dir().with_context(|| {
            format!(
                "{}: proving key location is not configured; set {} or {ARTIFACTS_DIR_ENV}",
                self.key, self.zkey_env
            )
        })?;
        Ok(root.join(self.zkey_file))
    }

    /// Read a pinned artifact and hard-fail on a digest mismatch.
    fn read_pinned(
        &self,
        path: &std::path::Path,
        expected: &str,
        what: &str,
        hint: &str,
    ) -> Result<Vec<u8>> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("{}: read {what} {} ({hint})", self.key, path.display()))?;
        let got = sha256_hex(&bytes);
        if got != expected {
            bail!(
                "{}: {what} sha256 mismatch at {}: got {got}, expected {expected} - wrong/stale artifact",
                self.key,
                path.display()
            );
        }
        Ok(bytes)
    }

    /// Verify the graph and proving-key digests.
    pub fn verify_artifacts(&self) -> Result<()> {
        self.read_pinned(
            &self.graph_path()?,
            self.graph_sha256,
            "graph",
            self.graph_env,
        )?;
        self.read_pinned(
            &self.zkey_path()?,
            self.zkey_sha256,
            "zkey",
            "set CURVY_ZK_KEYS_DIR",
        )?;
        Ok(())
    }

    /// Load and authenticate the evaluation graph.
    pub fn load_calculator(&self) -> Result<GraphWitnessCalculator> {
        let path = self.graph_path()?;
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "{}: read graph {} ({})",
                self.key,
                path.display(),
                self.graph_env
            )
        })?;
        GraphWitnessCalculator::from_graph_bytes(&bytes, self.graph_sha256).with_context(|| {
            format!(
                "{}: load graph {} - wrong/stale artifact",
                self.key,
                path.display()
            )
        })
    }

    /// Load and authenticate the proving key.
    pub fn load_prover(&self) -> Result<Prover> {
        let zkey = self.read_pinned(
            &self.zkey_path()?,
            self.zkey_sha256,
            "zkey",
            "set CURVY_ZK_KEYS_DIR",
        )?;
        Ok(Prover {
            inner: curvy_prover::Prover::from_zkey_bytes(&zkey, self.zkey_sha256)?,
            num_public: self.num_public,
        })
    }

    /// Generate and verify a Groth16 proof.
    pub fn prove(&self, input_json: &str) -> Result<ProofBundle> {
        let total_started = Instant::now();

        let phase_started = Instant::now();
        let calc = self.load_calculator()?;
        let graph_load_ms = phase_started.elapsed().as_millis() as u64;

        let phase_started = Instant::now();
        let prover = self.load_prover()?;
        let prover_load_ms = phase_started.elapsed().as_millis() as u64;

        let phase_started = Instant::now();
        let assignment = calc.calculate(input_json)?;
        let witness_ms = phase_started.elapsed().as_millis() as u64;

        let phase_started = Instant::now();
        let bundle = prover.prove_assignment(&assignment)?;
        let groth16_ms = phase_started.elapsed().as_millis() as u64;
        let total_ms = total_started.elapsed().as_millis() as u64;

        let timing = ProofTimingRecord {
            schema_version: 1,
            unix_time_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            circuit: self.key,
            graph_load_ms,
            prover_load_ms,
            witness_ms,
            groth16_ms,
            total_ms,
        };

        tracing::info!(
            circuit = self.key,
            graph_load_ms,
            prover_load_ms,
            witness_ms,
            groth16_ms,
            total_ms,
            "Curvy proof timing"
        );
        record_proof_timing(&timing);
        Ok(bundle)
    }
}

/// A pinned prover for one circuit.
pub struct Prover {
    inner: curvy_prover::Prover,
    num_public: usize,
}

/// A snarkjs-shaped proof + its public signals (decimal strings, witness order).
pub struct ProofBundle {
    pub proof_json: String,
    pub public_signals: Vec<String>,
}

impl Prover {
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle> {
        let bundle = self.inner.prove_assignment(assignment)?;
        let public_json = bundle.public_signals_json;
        let public_signals: Vec<String> =
            serde_json::from_str(&public_json).context("parse public signals")?;
        if public_signals.len() != self.num_public {
            bail!(
                "expected {} public signals, got {}",
                self.num_public,
                public_signals.len()
            );
        }
        Ok(ProofBundle {
            proof_json: bundle.proof_json,
            public_signals,
        })
    }
}
