# Vendored contract ABIs

`curvy-abi` consumes these ABI arrays at compile time to generate contract bindings.
Update them whenever a supported contract interface changes.

## Provenance

Extracted with `jq '.abi'` from the Hardhat artifacts published by the `curvy-bindings` crate,
whose `src/artifacts/*.json` are generated from the contract sources by
`packages/contracts/evm/rust/generate.sh` in the Curvy monorepo.

| | |
|---|---|
| `curvy-bindings` | 0.1.0-rc.5 |
| contract release | 1.0.0 |
| monorepo revision | `28fa505b64200dfc00a29e475a24779e809def0b` |

Re-vendoring from that crate — rather than hand-editing — is what keeps these in step with the
deployed contracts. The previous vendored set predated the direct-shield split and still declared
`autoShield`, which no longer exists on chain.

| file | contract |
|---|---|
| `CurvyAggregatorAlphaV2.abi.json` | Curvy aggregator |
| `CurvyVaultV2.abi.json` | Curvy vault |
| `PortalFactory.abi.json` | Portal factory |
| `Portal.abi.json` | Portal |
