# Circuit artifacts

Every circuit is calldata-bound: it takes the values the aggregator is sent, its words, as
private inputs, commits to them, and has three public signals, `[commitment, y, x]`.

Witness graphs use the `SIGNET01` format and are evaluated by `curvy-witness`.

At runtime `curvy-witnesscalc` resolves each graph like each proving key: the
circuit's own variable (`CURVY_<CIRCUIT>_GRAPH`) wins, otherwise the file is read
flat from `CURVY_ZK_KEYS_DIR`. The published crates do not carry these files; the
GitHub releases do. Only the `bundled-graphs` feature, for this repository's tests
and acceptance flow, falls back to `signet/` here.

Each file is a zstd frame around a version-1 body, which a stock `curvy-witness`
0.1.4 accepts with no feature flags. The pinned digest is that of the compressed file
on disk, which the evaluator authenticates.

The proving keys are the final keys of the trusted-setup ceremony of 27 October 2026. The
aggregators' verifiers are generated from them and released as circuit family `Core` version 1
(single aggregation, single withdrawal, pending) and `Pix` version 1 (PIX aggregation, PIX
withdrawal, pending).

| profile | graph in `CURVY_ZK_KEYS_DIR` (flat) | graph SHA-256 | zkey in `CURVY_ZK_KEYS_DIR` (flat) | zkey SHA-256 |
|---|---|---|---|---|
| pending `(256,30)` | `signet/pending-bound-256-30.signet.zst` | `513e381690b4626ebfc29cedd2abe3fbc7f56912df80083d4c49ef0debe2bbb6` | `verifyPendingNotesCommitmentBound_256_30-final.zkey` | `2f9462e2fd7994751212e7aa3c20dc6e284473876b828f31b90ac75d2479533b` |
| aggregation `(2,9,30,6)` | `signet/pix-aggregation-bound-2-9-30.signet.zst` | `334964e70daf187c66ee02af6c3061049458994de162ce6981c7a8eec7dc60f6` | `verifyPixAggregationBound_2_9_30-final.zkey` | `a7269ddecf820217aa103d9267e8884f3c7f37a8211f235c9f6c814f5786ed97` |
| multi-owner withdrawal `(10,30)` | `signet/pix-withdrawal-bound-10-30.signet.zst` | `cffbcdfb8131032b77691798d21f4e67f4d5290109cb76f2ae199d4de2077a02` | `verifyPixMultiOwnerWithdrawalBound_10_30-final.zkey` | `497cbdf95eb6a9b28aee527b710ef34b1edbaa7ad63631fbcdb492218db75b16` |
| withdrawal `(2,30)` | `signet/withdrawal-bound-2-30.signet.zst` | `9f5d967c273ffc1ef5abc5cb666fb139af8375ff6ca70688e765b2bc94f2bac8` | `verifySingleWithdrawalBound_2_30-final.zkey` | `b2446d46fc5acf647d7fd82d4a3a8289e568fcd2ff0d3309aa083efbfb29f07b` |
| aggregation `(2,3,30,6)` | `signet/aggregation-bound-2-3-30.signet.zst` | `bd11ff9d0d1aa9b8b7ca94c9873075e92606a82344358caaf6108ebc1dce620c` | `verifySingleAggregationBound_2_3_30-final.zkey` | `a5e8ba68d9abf0d26a5a8ab5d20f47a6d775370333279d30f8a0850334033e00` |

Artifact bytes are authenticated before decompression, graph decoding, or the
unchecked zkey point parser sees them. Wrong or stale files fail closed.

The artifact header carries the SHA-256 of the R1CS each graph was compiled from, which
`signet inspect` prints:

| profile | source R1CS SHA-256 | signals |
|---|---|---|
| pending `(256,30)` | `65fadecd7b460d1e118f2949a6a0c56fc51712e1226892c9b7b72f5a9f1314ca` | 93,268 |
| aggregation `(2,9,30,6)` | `75ced0cf8e0d05f23062d572ee3d0bd78a916e0d96775d1c39c20d6ef59e9cb5` | 60,865 |
| multi-owner withdrawal `(10,30)` | `624f14368c1f2007a203ef6b330540c1462461ebb419dea8894e5553ef6d2f91` | 161,710 |
| withdrawal `(2,30)` | `4695676526bde8360ac270e77ad9975ae24f74d8f7525f8fe11b9de465d9717d` | 25,183 |
| aggregation `(2,3,30,6)` | `bc2158521321d10ee2e757aae2b0918c0ead5d945574855ce5148bd3cff126ea` | 32,471 |

## What the tests check

`curvy-witnesscalc/tests/pix_profiles.rs` evaluates every graph on an input whose words
`curvy-witnesscalc` derived, and checks that the assignment's `[commitment, y, x]` is the binding
of those words. Proving with the pinned keys (`just test-proving`) checks the assignment satisfies
the circuit: every proof is verified against the zkey's verifying key before it is returned.
