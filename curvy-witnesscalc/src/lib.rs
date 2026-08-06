//! Witness generation and Groth16 proving for bundled Curvy circuits.
//!
//! Graphs and proving keys are authenticated by SHA-256 before use.

use anyhow::{Context, Result, bail};
use ark_bn254::Fr;
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub mod pending;
pub mod pix;

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
    graph_default: &'static str,
    graph_sha256: &'static str,
    zkey_env: &'static str,
    zkey_file: &'static str,
    zkey_sha256: &'static str,
    pub num_public: usize,
}

fn bundled_graphs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts/signet")
}

impl Circuit {
    pub fn withdrawal() -> Self {
        Circuit {
            key: "withdrawal",
            label: "withdrawal(2,30)",
            graph_env: "CURVY_WITHDRAWAL_GRAPH",
            graph_default: "withdrawal-2-30.signet.zst",
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
            graph_default: "aggregation-2-3-30.signet.zst",
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
            graph_default: "pix-aggregation-2-9-30.signet.zst",
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
            graph_default: "pix-withdrawal-10-30.signet.zst",
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
            graph_default: "pending-5-30.signet.zst",
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

    /// Resolved graph path, including environment overrides.
    pub fn graph_path(&self) -> PathBuf {
        std::env::var(self.graph_env)
            .map(PathBuf::from)
            .unwrap_or_else(|_| bundled_graphs().join(self.graph_default))
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
        let root = std::env::var_os("CURVY_ZK_KEYS_DIR").with_context(|| {
            format!(
                "{}: proving key location is not configured; set {} or CURVY_ZK_KEYS_DIR",
                self.key, self.zkey_env
            )
        })?;
        Ok(PathBuf::from(root).join(self.zkey_file))
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

    /// Load and authenticate the evaluation graph.
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
