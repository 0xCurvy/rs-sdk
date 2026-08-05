//! Pure-Rust witness generation + Groth16 proving for Curvy's deployed circuits.
//! A Curvy-owned `CVYWIT01` evaluation graph turns a circuit-input JSON into a
//! snarkjs-identical witness with no JS/node runtime, then `curvy-prover` proves it
//! into a snarkjs-shaped proof the deployed verifiers accept.
//!
//! ## Why CVYWIT and not iden3 `circom-witnesscalc`
//! Both evaluate the same circuit to the same assignment; `tests/pix_profiles.rs`
//! asserts that signal for signal. `curvy-witness` is preferred because it is ours,
//! it validates every graph reference before evaluating, and it is pure Rust - the
//! iden3 crate pulls in a `bindgen`/`clang` build requirement that broke the Nix and
//! bare-Linux setups this SDK has to run on. It survives as a dev-dependency purely
//! so the cross-evaluator equivalence gate can still be run.
//!
//! ## Artifact resolution (documented order)
//! Graphs and proving keys are pinned by sha256 and resolved per circuit:
//! 1. an env-var override (`CURVY_<CIRCUIT>_GRAPH` / `CURVY_<CIRCUIT>_ZKEY`);
//! 2. graphs use the authenticated files bundled under `artifacts/cvywit`;
//! 3. zkeys use their circuit-relative path under `CURVY_ZK_KEYS_DIR`.
//!
//! The zkeys remain external Git-LFS artifacts. Loading a graph or zkey whose
//! SHA-256 does not match the pin is a hard error: wrong artifact or wrong setup.

use anyhow::{Context, Result, bail};
use ark_bn254::Fr;
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub mod pending;
pub mod pix;

/// Circuit input JSON → the full BN254 witness assignment (index 0 is the constant
/// 1). The seam the SDK proves against; the graph impl is the only implementor today.
pub trait WitnessCalculator {
    fn calculate(&self, input_json: &str) -> Result<Vec<Fr>>;
}

/// A parsed, reusable `CVYWIT01` evaluation graph.
pub struct GraphWitnessCalculator {
    graph: WitnessGraph,
}

impl GraphWitnessCalculator {
    /// Authenticate and parse one graph. `WitnessGraph::from_bytes` hashes the
    /// complete artifact before decoding anything, so this is the pin check - there
    /// is deliberately no second pass over the same bytes.
    pub fn from_graph_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        Ok(Self {
            graph: WitnessGraph::from_bytes(bytes, expected_sha256)?,
        })
    }

    /// Signal count this graph produces, i.e. the assignment length the paired zkey
    /// must expect.
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

/// One deployed circuit config: pinned graph + zkey and on-chain arity.
pub struct Circuit {
    pub key: &'static str,
    pub label: &'static str,
    graph_env: &'static str,
    graph_default: &'static str,
    graph_sha256: &'static str,
    zkey_env: &'static str,
    zkey_relative: &'static str,
    zkey_sha256: &'static str,
    pub num_public: usize,
}

fn bundled_graphs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts/cvywit")
}

impl Circuit {
    pub fn withdrawal() -> Self {
        Circuit {
            key: "withdrawal",
            label: "withdrawal(2,30)",
            graph_env: "CURVY_WITHDRAWAL_GRAPH",
            graph_default: "withdrawal-2-30.cvywit.bin",
            graph_sha256: "71295ae000c466d2111969cb335597f63c1a1a3d3990878d4b996757fa9998d3",
            zkey_env: "CURVY_WITHDRAWAL_ZKEY",
            zkey_relative: "withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey",
            zkey_sha256: "c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716",
            num_public: 6,
        }
    }

    pub fn aggregation() -> Self {
        Circuit {
            key: "aggregation",
            label: "aggregation(2,3,30,6)",
            graph_env: "CURVY_AGGREGATION_GRAPH",
            graph_default: "aggregation-2-3-30.cvywit.bin",
            graph_sha256: "eec4484ede443daf34947e0e622951da2749d5d919f10cf7560bd19a430e08dd",
            zkey_env: "CURVY_AGGREGATION_ZKEY",
            zkey_relative: "aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey",
            zkey_sha256: "88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6",
            num_public: 31,
        }
    }

    pub fn pix_aggregation() -> Self {
        Circuit {
            key: "pix-aggregation",
            label: "pix-aggregation(2,9,30,6)",
            graph_env: "CURVY_PIX_AGGREGATION_GRAPH",
            graph_default: "pix-aggregation-2-9-30.cvywit.bin",
            graph_sha256: "3189a0dea620d68e0beeb7b3987367e94cee7b4f5574d8ef797eec0f4365ece9",
            zkey_env: "CURVY_PIX_AGGREGATION_ZKEY",
            zkey_relative: "pix/aggregation/verifyPixAggregation_2_9_30_evaluation.zkey",
            zkey_sha256: "b4fced8a3c183d25a13a24c9ee7234ec96b77f87f688992ee07144f23ace6750",
            num_public: 67,
        }
    }

    pub fn pix_withdrawal() -> Self {
        Circuit {
            key: "pix-withdrawal",
            label: "pix-withdrawal(10,30)",
            graph_env: "CURVY_PIX_WITHDRAWAL_GRAPH",
            graph_default: "pix-withdrawal-10-30.cvywit.bin",
            graph_sha256: "99f69d992b0aed23cbac86a3cd27c3983f2240d45c405ba0a9e37ee8d59ecbf0",
            zkey_env: "CURVY_PIX_WITHDRAWAL_ZKEY",
            zkey_relative: "pix/withdrawal/verifyPixMultiOwnerWithdrawal_10_30_evaluation.zkey",
            zkey_sha256: "e18f0fdd40aa2643c31c3a02ef0a508b5c7580a436abcae88e364ee86be6a95b",
            num_public: 14,
        }
    }

    pub fn pending() -> Self {
        Circuit {
            key: "pending",
            label: "pending-notes-commitment(5,30)",
            graph_env: "CURVY_PENDING_GRAPH",
            graph_default: "pending-5-30.cvywit.bin",
            graph_sha256: "cdbaa9072b962689b648991a4dac4a863305d9e9db341e98fa0a48d89d0f6a37",
            zkey_env: "CURVY_PENDING_ZKEY",
            zkey_relative: "pending-notes-commitment/verifyPendingNotesCommitment_5_30_0001.zkey",
            zkey_sha256: "efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847",
            num_public: 1,
        }
    }

    /// Every circuit the PIX acceptance flow proves, in the order it uses them.
    /// Handy for an up-front artifact preflight (see [`verify_artifacts`](Self::verify_artifacts)).
    pub fn pix_flow() -> [Self; 3] {
        [
            Circuit::pending(),
            Circuit::pix_aggregation(),
            Circuit::pix_withdrawal(),
        ]
    }

    /// Resolved location of this circuit's evaluation graph, honouring the env override.
    pub fn graph_path(&self) -> PathBuf {
        std::env::var(self.graph_env)
            .map(PathBuf::from)
            .unwrap_or_else(|_| bundled_graphs().join(self.graph_default))
    }

    /// The pinned graph digest. Exposed so a consumer can authenticate the artifact
    /// itself - the SDK re-exports this crate precisely for that.
    pub fn graph_sha256(&self) -> &'static str {
        self.graph_sha256
    }
    fn zkey_path(&self) -> Result<PathBuf> {
        if let Some(path) = std::env::var_os(self.zkey_env) {
            return Ok(PathBuf::from(path));
        }
        let root = std::env::var_os("CURVY_ZK_KEYS_DIR").with_context(|| {
            format!(
                "{}: proving key location is not configured; set {} or CURVY_ZK_KEYS_DIR",
                self.key, self.zkey_env
            )
        })?;
        Ok(PathBuf::from(root).join(self.zkey_relative))
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

    /// Resolve and pin-check this circuit's graph **and** proving key without
    /// parsing either. The point is failing fast: a missing `CURVY_ZK_KEYS_DIR` or a
    /// stale zkey otherwise only surfaces minutes into a run, after the deposit and
    /// the first commitment have already hit the chain.
    pub fn verify_artifacts(&self) -> Result<()> {
        self.read_pinned(
            &self.graph_path(),
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

    /// Load + pin-check the evaluation graph. The parser authenticates the artifact
    /// itself, so the bytes are read once and hashed once.
    pub fn load_calculator(&self) -> Result<GraphWitnessCalculator> {
        let path = self.graph_path();
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

    /// Load + pin-check the proving key into a `curvy-prover::Prover`.
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

    /// End-to-end for this circuit: input JSON → pure-Rust witness → Groth16 proof.
    /// Verifies off-chain before returning (a fast failure localizes to witness/zkey).
    pub fn prove(&self, input_json: &str) -> Result<ProofBundle> {
        let calc = self.load_calculator()?;
        let prover = self.load_prover()?;
        let assignment = calc.calculate(input_json)?;
        prover.prove_assignment(&assignment)
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
