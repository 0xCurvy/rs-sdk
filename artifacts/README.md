# Circuit artifacts

Witness graphs are Curvy's own `CVYWIT01` format, evaluated by `curvy-witness`. They
are fixed to the exact `v3-pix-circuits` evaluation profiles used by the local Blokli
deployment.

| profile | graph | graph SHA-256 | zkey relative to `CURVY_ZK_KEYS_DIR` | zkey SHA-256 |
|---|---|---|---|---|
| pending `(5,30)` | `cvywit/pending-5-30.cvywit.bin` | `cdbaa9072b962689b648991a4dac4a863305d9e9db341e98fa0a48d89d0f6a37` | `pending-notes-commitment/verifyPendingNotesCommitment_5_30_0001.zkey` | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` |
| PIX aggregation `(2,9,30,6)` | `cvywit/pix-aggregation-2-9-30.cvywit.bin` | `3189a0dea620d68e0beeb7b3987367e94cee7b4f5574d8ef797eec0f4365ece9` | `pix/aggregation/verifyPixAggregation_2_9_30_evaluation.zkey` | `b4fced8a3c183d25a13a24c9ee7234ec96b77f87f688992ee07144f23ace6750` |
| PIX withdrawal `(10,30)` | `cvywit/pix-withdrawal-10-30.cvywit.bin` | `99f69d992b0aed23cbac86a3cd27c3983f2240d45c405ba0a9e37ee8d59ecbf0` | `pix/withdrawal/verifyPixMultiOwnerWithdrawal_10_30_evaluation.zkey` | `e18f0fdd40aa2643c31c3a02ef0a508b5c7580a436abcae88e364ee86be6a95b` |
| withdrawal `(2,30)` | `cvywit/withdrawal-2-30.cvywit.bin` | `71295ae000c466d2111969cb335597f63c1a1a3d3990878d4b996757fa9998d3` | `withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey` | `c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716` |
| aggregation `(2,3,30,6)` | `cvywit/aggregation-2-3-30.cvywit.bin` | `eec4484ede443daf34947e0e622951da2749d5d919f10cf7560bd19a430e08dd` | `aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey` | `88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6` |

Artifact bytes are authenticated before graph decoding or the unchecked zkey point
parser sees them. Wrong/stale files fail closed.

## `graphs/` — test fixtures only

`graphs/*.graph.bin` are the iden3 `circom-witnesscalc` graphs for the three PIX
circuits. Nothing on the production path reads them. They exist so
`curvy-witnesscalc/tests/pix_profiles.rs` can evaluate each input through an
independently built graph and compare the resulting assignment to the CVYWIT one,
signal for signal. That comparison is the evidence the CVYWIT graphs are faithful, so
the fixtures are pinned by SHA-256 too — a stale reference would make the test pass
without meaning anything.

`circom-witnesscalc` is therefore a **dev-dependency only**. It needs `bindgen`/`clang`,
which the Nix and bare-Linux targets do not have; `cargo build -p curvy-e2e` never
compiles it, only `cargo test -p curvy-witnesscalc` does.

## `cvywit/*.postcard.bin`

Intermediate output of the `circom-witness-rs` generation pipeline, kept so a graph can
be re-exported (v1 or v2) without re-running circom. Not read at runtime.
