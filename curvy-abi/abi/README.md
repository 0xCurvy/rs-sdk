# Vendored contract ABIs

`curvy-abi` consumes these ABI arrays at compile time to generate contract bindings.
Update them whenever a supported contract interface changes.

## Source

Extracted with `jq '.abi'` from the compiled artifacts of the Curvy contracts.

The aggregator's `commitPendingNotes`, `submitAggregationRequest` and `submitWithdrawalRequest`
take the circuit family version the proof was made for, `CircuitRef { family, version }`, and
their values as calldata words with the proof's `commitment`, and verify the three public
signals `[commitment, y, x]`. `latestCircuitVersion`, `circuitVersionStatus` and `getVerifier`
read the released versions.

| file | contract |
|---|---|
| `CurvyAggregatorAlphaV2.abi.json` | Curvy aggregator |
| `CurvyVaultV2.abi.json` | Curvy vault |
| `PortalFactory.abi.json` | Portal factory |
| `Portal.abi.json` | Portal |
