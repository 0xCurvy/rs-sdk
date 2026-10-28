//! Witness generation and Groth16 proving for the Curvy circuits.
//!
//! Every pinned circuit is bound to calldata: the values the aggregator takes, its words, are
//! private inputs the circuit commits to, and its only public signals are `[commitment, y, x]`
//! ([`curvy_core::calldata`]). [`Circuit::prove_bound`] derives the words from the input, binds
//! them, proves with `x` and checks the proof's signals against the binding; the caller sends the
//! words and the commitment to the contract with the proof.
//!
//! Every circuit needs two artifacts at runtime: a `SIGNET01` witness graph and a Groth16
//! proving key. Both are resolved the same way - a circuit-specific environment variable
//! wins, otherwise the file is looked up flat under [`ARTIFACTS_DIR_ENV`], or under the
//! directory compiled in through [`ARTIFACTS_DIR_DEFAULT_ENV`] when that is unset - and both
//! are authenticated by SHA-256 before use. The artifacts ship with the SDK's GitHub releases
//! and its Nix flake, not with the crate. Only the `bundled-graphs` feature, meant for this
//! repository's own tests and acceptance flow, falls back to the graphs checked into the
//! source tree.

use anyhow::{Context, Result, bail};
use ark_bn254::Fr;
use curvy_core::calldata::{CalldataBinding, bind_calldata};
use curvy_core::field::fr_to_dec;
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
pub mod words;

use words::Layout;

/// Optional newline-delimited JSON destination for proof timing records.
///
/// This is deliberately separate from `tracing`: acceptance tests run proofs on blocking
/// worker threads and must retain measurements even when a subscriber filter changes or the
/// process is terminated immediately after the protocol completes.
pub const PROOF_TIMINGS_PATH_ENV: &str = "CURVY_PROOF_TIMINGS_PATH";

/// Directory holding the witness graphs and proving keys, flat, one file per circuit.
///
/// Circuit-specific overrides (`CURVY_<CIRCUIT>_GRAPH`, `CURVY_<CIRCUIT>_ZKEY`) take
/// precedence over it; [`ARTIFACTS_DIR_DEFAULT`] is the fallback when it is unset.
pub const ARTIFACTS_DIR_ENV: &str = "CURVY_ZK_KEYS_DIR";

/// Build-time name of the same variable, read when this crate is compiled.
///
/// A packaged build that knows where its artifacts will live — a Nix build, say, where the
/// directory is a store path fixed at build time — sets it, and the resulting binary finds
/// them with nothing to configure at run time. It is the last resort: [`ARTIFACTS_DIR_ENV`]
/// and the circuit-specific variables still win when set.
pub const ARTIFACTS_DIR_DEFAULT_ENV: &str = "CURVY_ZK_KEYS_DIR_DEFAULT";

/// Artifacts directory compiled in through [`ARTIFACTS_DIR_DEFAULT_ENV`], if any.
pub const ARTIFACTS_DIR_DEFAULT: Option<&str> = option_env!("CURVY_ZK_KEYS_DIR_DEFAULT");

fn artifacts_dir() -> Option<PathBuf> {
    std::env::var_os(ARTIFACTS_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| ARTIFACTS_DIR_DEFAULT.map(PathBuf::from))
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

/// The public signals of every bound circuit: `[commitment, y, x]`.
pub const BOUND_PUBLIC_SIGNALS: usize = 3;

/// The `Core` family version the aggregators released the pinned single aggregation, single
/// withdrawal and pending-notes keys as.
pub const CORE_CIRCUIT_VERSION: u64 = 1;

/// The `Pix` family version the aggregators released the pinned PIX aggregation, PIX withdrawal
/// and pending-notes keys as.
pub const PIX_CIRCUIT_VERSION: u64 = 1;

/// Pinned graph, proving key, and the layout of the words the circuit is bound to.
pub struct Circuit {
    pub key: &'static str,
    pub label: &'static str,
    graph_env: &'static str,
    graph_file: &'static str,
    graph_sha256: &'static str,
    zkey_env: &'static str,
    zkey_file: &'static str,
    zkey_sha256: &'static str,
    pub layout: Layout,
    pub num_public: usize,
}

/// A proof of a bound circuit, with what the aggregator is sent next to it.
#[derive(Clone, Debug)]
pub struct BoundProof {
    pub proof_json: String,
    /// The values the entry point takes as calldata, in its order.
    pub words: Vec<Fr>,
    /// The proof's public signals, `[commitment, y, x]`, as bound to [`Self::words`].
    pub binding: CalldataBinding,
}

impl BoundProof {
    /// The words as decimal strings, as the encoders and the relayer take them.
    pub fn words_dec(&self) -> Vec<String> {
        self.words.iter().map(fr_to_dec).collect()
    }

    /// The commitment sent with the words, as a decimal string.
    pub fn commitment_dec(&self) -> String {
        fr_to_dec(&self.binding.commitment)
    }
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
            label: "withdrawal-bound(2,30)",
            graph_env: "CURVY_WITHDRAWAL_GRAPH",
            graph_file: "withdrawal-bound-2-30.signet.zst",
            graph_sha256: "9f5d967c273ffc1ef5abc5cb666fb139af8375ff6ca70688e765b2bc94f2bac8",
            zkey_env: "CURVY_WITHDRAWAL_ZKEY",
            zkey_file: "verifySingleWithdrawalBound_2_30-final.zkey",
            zkey_sha256: "b2446d46fc5acf647d7fd82d4a3a8289e568fcd2ff0d3309aa083efbfb29f07b",
            layout: Layout::Withdrawal {
                zero_padding_nullifiers: false,
            },
            num_public: BOUND_PUBLIC_SIGNALS,
        }
    }

    pub fn aggregation() -> Self {
        Circuit {
            key: "aggregation",
            label: "aggregation-bound(2,3,30,6)",
            graph_env: "CURVY_AGGREGATION_GRAPH",
            graph_file: "aggregation-bound-2-3-30.signet.zst",
            graph_sha256: "bd11ff9d0d1aa9b8b7ca94c9873075e92606a82344358caaf6108ebc1dce620c",
            zkey_env: "CURVY_AGGREGATION_ZKEY",
            zkey_file: "verifySingleAggregationBound_2_3_30-final.zkey",
            zkey_sha256: "a5e8ba68d9abf0d26a5a8ab5d20f47a6d775370333279d30f8a0850334033e00",
            layout: Layout::Aggregation,
            num_public: BOUND_PUBLIC_SIGNALS,
        }
    }

    pub fn pix_aggregation() -> Self {
        Circuit {
            key: "pix-aggregation",
            label: "pix-aggregation-bound(2,9,30,6)",
            graph_env: "CURVY_PIX_AGGREGATION_GRAPH",
            graph_file: "pix-aggregation-bound-2-9-30.signet.zst",
            graph_sha256: "334964e70daf187c66ee02af6c3061049458994de162ce6981c7a8eec7dc60f6",
            zkey_env: "CURVY_PIX_AGGREGATION_ZKEY",
            zkey_file: "verifyPixAggregationBound_2_9_30-final.zkey",
            zkey_sha256: "a7269ddecf820217aa103d9267e8884f3c7f37a8211f235c9f6c814f5786ed97",
            layout: Layout::Aggregation,
            num_public: BOUND_PUBLIC_SIGNALS,
        }
    }

    pub fn pix_withdrawal() -> Self {
        Circuit {
            key: "pix-withdrawal",
            label: "pix-withdrawal-bound(10,30)",
            graph_env: "CURVY_PIX_WITHDRAWAL_GRAPH",
            graph_file: "pix-withdrawal-bound-10-30.signet.zst",
            graph_sha256: "cffbcdfb8131032b77691798d21f4e67f4d5290109cb76f2ae199d4de2077a02",
            zkey_env: "CURVY_PIX_WITHDRAWAL_ZKEY",
            zkey_file: "verifyPixMultiOwnerWithdrawalBound_10_30-final.zkey",
            zkey_sha256: "497cbdf95eb6a9b28aee527b710ef34b1edbaa7ad63631fbcdb492218db75b16",
            layout: Layout::Withdrawal {
                zero_padding_nullifiers: true,
            },
            num_public: BOUND_PUBLIC_SIGNALS,
        }
    }

    pub fn pending() -> Self {
        Circuit {
            key: "pending",
            label: "pending-notes-commitment-bound(256,30)",
            graph_env: "CURVY_PENDING_GRAPH",
            graph_file: "pending-bound-256-30.signet.zst",
            graph_sha256: "513e381690b4626ebfc29cedd2abe3fbc7f56912df80083d4c49ef0debe2bbb6",
            zkey_env: "CURVY_PENDING_ZKEY",
            zkey_file: "verifyPendingNotesCommitmentBound_256_30-final.zkey",
            zkey_sha256: "2f9462e2fd7994751212e7aa3c20dc6e284473876b828f31b90ac75d2479533b",
            layout: Layout::PendingCommitment,
            num_public: BOUND_PUBLIC_SIGNALS,
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

    /// Prove `input`, the circuit's input without `x`, bound to the words it derives.
    ///
    /// The words come from the input by [`Self::layout`], the binding from the words, and the
    /// proof is made with the binding's `x` and refused unless its public signals are the
    /// binding's `[commitment, y, x]`. A pending-notes commitment is proved with
    /// [`pending::prove`] instead: its words depend on the notes tree.
    pub fn prove_bound(&self, input: &serde_json::Value) -> Result<BoundProof> {
        let words = words::from_input(self.layout, input)
            .with_context(|| format!("{}: calldata words", self.key))?;
        let binding =
            bind_calldata(&words).with_context(|| format!("{}: bind calldata words", self.key))?;
        let mut input = input.clone();
        let fields = input
            .as_object_mut()
            .with_context(|| format!("{}: circuit input is not an object", self.key))?;
        if fields
            .insert(
                "x".to_owned(),
                serde_json::Value::String(fr_to_dec(&binding.x)),
            )
            .is_some()
        {
            bail!("{}: circuit input already carries x", self.key);
        }
        self.prove_bound_input(&serde_json::to_string(&input)?, words, binding)
    }

    /// Prove `input_json`, which carries `binding.x`, and check the proof is bound to `words`.
    pub(crate) fn prove_bound_input(
        &self,
        input_json: &str,
        words: Vec<Fr>,
        binding: CalldataBinding,
    ) -> Result<BoundProof> {
        let bundle = self.prove(input_json)?;
        let expected = binding.public_signals().map(|signal| fr_to_dec(&signal));
        if bundle.public_signals != expected {
            bail!(
                "{}: the proof is not bound to its words (public signals {:?}, expected {:?}); \
                 the words disagree with the circuit or the artifacts are not the bound circuit's",
                self.key,
                bundle.public_signals,
                expected
            );
        }
        Ok(BoundProof {
            proof_json: bundle.proof_json,
            words,
            binding,
        })
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
