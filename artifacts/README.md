# Circuit artifacts

Witness graphs use the `SIGNET01` format and are evaluated by `curvy-witness`.

At runtime `curvy-witnesscalc` resolves each graph like each proving key: the
circuit's own variable (`CURVY_<CIRCUIT>_GRAPH`) wins, otherwise the file is read
flat from `CURVY_ZK_KEYS_DIR`. The published crates do not carry these files; the
GitHub releases do. Only the `bundled-graphs` feature, for this repository's tests
and acceptance flow, falls back to `signet/` here.

Each file is a zstd frame around a version-1 body, which a stock `curvy-witness`
0.1.0-rc.3 accepts with no feature flags. The pinned digest is the digest of the file
as it sits on disk, compressed: that is what the evaluator is handed and therefore
what it authenticates.

| profile | graph in `CURVY_ZK_KEYS_DIR` (flat) | graph SHA-256 | zkey in `CURVY_ZK_KEYS_DIR` (flat) | zkey SHA-256 |
|---|---|---|---|---|
| pending `(5,30)` | `signet/pending-5-30.signet.zst` | `69fa449825732a0958ccd0689ad361d9e8df1223231d8b71932d0efc4a07d8f0` | `verifyPendingNotesCommitment_5_30_0001.zkey` | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` |
| aggregation `(2,9,30,6)` | `signet/pix-aggregation-2-9-30.signet.zst` | `b974028ba40afdc067524819d61bdd9172a5e56369cfc05a75ba5d469c379c3a` | `verifyPixAggregation_2_9_30_evaluation.zkey` | `b4fced8a3c183d25a13a24c9ee7234ec96b77f87f688992ee07144f23ace6750` |
| multi-owner withdrawal `(10,30)` | `signet/pix-withdrawal-10-30.signet.zst` | `90d301a189ceea1a7574f410bd94e53e9da0da0e75d8bfb99d47c42295fdfa56` | `verifyPixMultiOwnerWithdrawal_10_30_evaluation.zkey` | `e18f0fdd40aa2643c31c3a02ef0a508b5c7580a436abcae88e364ee86be6a95b` |
| withdrawal `(2,30)` | `signet/withdrawal-2-30.signet.zst` | `04b2fa84394548a971c757c61280b81fb7699a367eeb45834201675f8a0aad74` | `verifySingleWithdrawalNoHashing_2_30_0001.zkey` | `c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716` |
| aggregation `(2,3,30,6)` | `signet/aggregation-2-3-30.signet.zst` | `8c6eb16f41cc147fca8809804c0f0743d463aeba2ee45a02e7b32b6a27904386` | `verifySingleAggregationNoHashing_2_3_30_0001.zkey` | `88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6` |

Artifact bytes are authenticated before decompression, graph decoding, or the
unchecked zkey point parser sees them. Wrong or stale files fail closed.

The source R1CS each graph was compiled from, which is provenance rather than a
second trust root, is carried in the artifact header and printed by
`signet inspect`:

| profile | source R1CS SHA-256 | signals |
|---|---|---|
| pending `(5,30)` | `150cc21f7bb6384a6b691a299319b86fc9bc69a361d7a52a3895f0792e5b1a44` | 224,505 |
| aggregation `(2,9,30,6)` | `14169484b4daac9001d33769f4fe1ce75244c6e855a604a6b28d169499fff4f4` | 57,207 |
| multi-owner withdrawal `(10,30)` | `7deeb09cf5ae34fd080794ceadc2e24bde64734edc353301bd4d3b4b82f1369b` | 162,449 |
| withdrawal `(2,30)` | `4b105f8650463b07b26f1798ffa7b6e9a9290863c2faf016615577e5cce5dd5a` | 21,502 |
| aggregation `(2,3,30,6)` | `fdbf71a667f3deff6f76b7ef959fbb92447eff0afb2d4b9c230b341636e626b8` | 27,444 |

## `graphs/` test fixtures

`graphs/*.graph.bin` are iden3 `circom-witnesscalc` graphs for three circuits.
Nothing on the production path reads them. They exist so
`curvy-witnesscalc/tests/pix_profiles.rs` can evaluate each input through an
independently built graph and compare the resulting assignment to the SIGNET one,
signal for signal. That comparison is the evidence the SIGNET graphs are faithful, so
the fixtures are pinned by SHA-256 too: a stale reference would make the test pass
without meaning anything.

`circom-witnesscalc` is therefore a **dev-dependency only**. It needs `bindgen` and
`clang`, which the Nix and bare-Linux targets do not have; `cargo build -p curvy-e2e`
never compiles it, only `cargo test -p curvy-witnesscalc` does.
