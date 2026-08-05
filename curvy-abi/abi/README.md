# Vendored contract ABIs — provenance

These four `*.abi.json` files are the `.abi` arrays extracted verbatim from the
compiled artifacts in the **read-only** `v3-pix-circuits` checkout, so the SDK never
reads that repository at build or run time. `curvy-abi`'s `sol!` macro consumes them at
**compile time** to generate the bindings.

| file | source artifact (`v3-pix-circuits`) |
|---|---|
| `CurvyAggregatorAlphaV2.abi.json` | `packages/contracts/evm/artifacts/src/v2/aggregator-alpha/CurvyAggregatorAlphaV2.sol/CurvyAggregatorAlphaV2.json` → `.abi` |
| `CurvyVaultV2.abi.json`           | `packages/contracts/evm/artifacts/src/v2/vault/CurvyVaultV2.sol/CurvyVaultV2.json` → `.abi` |
| `PortalFactory.abi.json`          | `packages/contracts/evm/artifacts/src/v2/portal/PortalFactory.sol/PortalFactory.json` → `.abi` |
| `Portal.abi.json`                 | `packages/contracts/evm/artifacts/src/v2/portal/Portal.sol/Portal.json` → `.abi` |

Extraction command (recorded for reproducibility):

```bash
V3=…/v3-pix-circuits/packages/contracts/evm/artifacts/src/v2
jq '.abi' $V3/aggregator-alpha/CurvyAggregatorAlphaV2.sol/CurvyAggregatorAlphaV2.json > CurvyAggregatorAlphaV2.abi.json
# … likewise for the other three
```

The normalized ABI arrays were compared against the current compiled artifacts:
aggregator `ad5ab70a…`, vault `6f997c46…`, factory `d371ac37…`, and portal
`776a2676…`. Re-extract and update these provenance values if the contracts change.
