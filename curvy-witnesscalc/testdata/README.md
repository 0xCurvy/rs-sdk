# Test proving keys

`multiplier.zkey` is the `c <== a * b` test key rs-core's prover tests use
(`crates/prover/testdata` there, from `ark-circom` 0.6.0, MIT OR Apache-2.0).
`multiplier.czkey` is the same key as a compact zkey, copied from there too.
The proving-key loader's tests read both; they are not ceremony keys.

- `multiplier.zkey`: `320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f`
- `multiplier.czkey`: `d3589b5b0ce19a00e99354f8bbc73524263fa110246fe1ae966d8ebcd5e98bc2`
