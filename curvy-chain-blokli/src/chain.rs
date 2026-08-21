//! Blokli-backed contract-read adapters.
//!
//! ## Encodings
//! Wire conversions are centralized here:
//!
//! | wire type | example fields | this seam wants |
//! |---|---|---|
//! | `Hex32` | `notesTreeRoot`, `noteId`, `commitmentFeeRoot` | decimal [`Dec`] |
//! | `UInt256` | fees, `ephemeralKey`, `feeNotePublicKey` | decimal already |
//! | `TokenValueString` | `nativeBalance.balance` | wei (it is *not* wei on the wire) |

use async_trait::async_trait;
use curvy_chain_api::{
    BalanceReader, ChainError, FeeConfigSource, PortalDirectory, Result, RootAnchor,
};
use curvy_types::{Addr, AggregatorState, Dec, FeeConfig, GasFees};
use num_bigint::BigUint;

use crate::{BlokliChain, hex32_field, is_not_found, string_field, u64_field, union_node};

const AGGREGATOR_STATE_QUERY: &str = r#"
query {
  curvyAggregatorState {
    __typename
    ... on CurvyAggregatorState { notesTreeRoot notesBatchIndex nullifiersBatchIndex noteIndex }
    ... on QueryFailedError { code message }
  }
}"#;

const VALID_NOTES_ROOT_QUERY: &str = r#"
query ($root: Hex32!) {
  curvyValidNotesRoot(root: $root) {
    __typename
    ... on CurvyBooleanValue { value }
    ... on QueryFailedError { code message }
  }
}"#;

const NOTE_STATUS_QUERY: &str = r#"
query ($noteId: Hex32!) {
  curvyNoteStatus(noteId: $noteId) {
    __typename
    ... on CurvyNoteStatus { status }
    ... on QueryFailedError { code message }
  }
}"#;

const VAULT_FEES_QUERY: &str = r#"
query {
  curvyVaultFees {
    __typename
    ... on CurvyVaultFees { depositFee withdrawalFee }
    ... on QueryFailedError { code message }
  }
  curvyAggregatorFees {
    __typename
    ... on CurvyAggregatorFees { protocolFeePerThousand commitmentFeeRoot feeNotePublicKey }
    ... on QueryFailedError { code message }
  }
  curvyVaultTokenCount {
    __typename
    ... on CurvyVaultTokenCount { count }
    ... on QueryFailedError { code message }
  }
}"#;

const VAULT_TOKEN_QUERY: &str = r#"
query ($tokenId: UInt256!) {
  curvyVaultToken(tokenId: $tokenId) {
    __typename
    ... on CurvyVaultToken {
      tokenAddress
      gasFees { tokenId portalDeployment pendingNoteCommitment withdrawal }
    }
    ... on QueryFailedError { code message }
  }
}"#;

const NATIVE_BALANCE_QUERY: &str = r#"
query ($address: String!) {
  nativeBalance(address: $address) {
    __typename
    ... on NativeBalance { address balance }
    ... on InvalidAddressError { code message }
    ... on QueryFailedError { code message }
  }
}"#;

const HOPR_BALANCE_QUERY: &str = r#"
query ($address: String!) {
  hoprBalance(address: $address, token: HOPR) {
    __typename
    ... on HoprBalance { address balance }
    ... on InvalidAddressError { code message }
    ... on QueryFailedError { code message }
  }
  chainInfo {
    __typename
    ... on ChainInfo { contractAddresses }
  }
}"#;

const TRANSACTION_COUNT_QUERY: &str = r#"
query ($address: String!) {
  transactionCount(address: $address) {
    __typename
    ... on TransactionCount { address count }
    ... on InvalidAddressError { code message }
    ... on QueryFailedError { code message }
  }
}"#;

const GAS_AND_CHAIN_QUERY: &str = r#"
query { chainInfo { __typename ... on ChainInfo { chainId gasPrice } } }"#;

const ENTRY_PORTAL_QUERY: &str = r#"
query ($ownerHash: UInt256!, $recovery: String!) {
  curvyEntryPortalAddress(ownerHash: $ownerHash, recovery: $recovery) {
    __typename
    ... on CurvyAddress { address }
    ... on InvalidAddressError { code message }
    ... on QueryFailedError { code message }
  }
}"#;

const PORTAL_REGISTERED_QUERY: &str = r#"
query ($portalAddress: String!) {
  curvyPortalRegistered(portalAddress: $portalAddress) {
    __typename
    ... on CurvyBooleanValue { value }
    ... on InvalidAddressError { code message }
    ... on QueryFailedError { code message }
  }
}"#;

/// Native-token decimals; `nativeBalance` renders its value scaled by this.
const NATIVE_DECIMALS: usize = 18;

/// Render a decimal field element as the `0x`-prefixed 64-hex-char `Hex32` the Curvy
/// contract-read arguments take. The inverse of [`hex32_field`].
fn dec_to_hex32(value: &Dec) -> Result<String> {
    let parsed = value.parse::<BigUint>().map_err(|error| {
        ChainError::Decode(format!("not a decimal field value {value:?}: {error}"))
    })?;
    let hex = format!("{parsed:x}");
    if hex.len() > 64 {
        return Err(ChainError::Decode(format!(
            "value {value} does not fit in 32 bytes"
        )));
    }
    Ok(format!("0x{hex:0>64}"))
}

/// Convert `TokenValueString` into wei.
fn token_value_to_wei(raw: &str) -> Result<Dec> {
    let amount = raw.split_whitespace().next().unwrap_or_default();
    if amount.is_empty() {
        return Err(ChainError::Decode(format!("empty token value {raw:?}")));
    }
    let (integer, fraction) = match amount.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (amount, ""),
    };
    if fraction.len() > NATIVE_DECIMALS {
        return Err(ChainError::Decode(format!(
            "token value {raw:?} has more than {NATIVE_DECIMALS} decimals"
        )));
    }
    let mut digits = String::with_capacity(integer.len() + NATIVE_DECIMALS);
    digits.push_str(integer);
    digits.push_str(fraction);
    for _ in fraction.len()..NATIVE_DECIMALS {
        digits.push('0');
    }
    digits
        .parse::<BigUint>()
        .map(|value| value.to_str_radix(10))
        .map_err(|error| ChainError::Decode(format!("token value {raw:?}: {error}")))
}

/// A `UInt256` decimal field parsed as `u64`.
fn uint256_u64(value: &serde_json::Value, name: &str) -> Result<u64> {
    string_field(value, name)?
        .parse()
        .map_err(|error| ChainError::Decode(format!("{name} does not fit u64: {error}")))
}

#[async_trait]
impl RootAnchor for BlokliChain {
    async fn state(&self) -> Result<AggregatorState> {
        let response = self
            .gql(AGGREGATOR_STATE_QUERY, serde_json::json!({}))
            .await?;
        let node = union_node(&response, "curvyAggregatorState")?;
        Ok(AggregatorState {
            current_notes_root: hex32_field(node, "notesTreeRoot")?,
            current_note_index: uint256_u64(node, "noteIndex")?,
            current_notes_batch_index: uint256_u64(node, "notesBatchIndex")?,
            current_nullifiers_batch_index: uint256_u64(node, "nullifiersBatchIndex")?,
        })
    }

    async fn is_valid_notes_root(&self, root: &Dec) -> Result<bool> {
        let response = self
            .gql(
                VALID_NOTES_ROOT_QUERY,
                serde_json::json!({ "root": dec_to_hex32(root)? }),
            )
            .await?;
        let node = union_node(&response, "curvyValidNotesRoot")?;
        node["value"]
            .as_bool()
            .ok_or_else(|| ChainError::Decode(format!("curvyValidNotesRoot has no value: {node}")))
    }

    async fn note_status(&self, note_id: &Dec) -> Result<u8> {
        let response = self
            .gql(
                NOTE_STATUS_QUERY,
                serde_json::json!({ "noteId": dec_to_hex32(note_id)? }),
            )
            .await?;
        let node = union_node(&response, "curvyNoteStatus")?;
        let status = node["status"]
            .as_i64()
            .ok_or_else(|| ChainError::Decode(format!("curvyNoteStatus has no status: {node}")))?;
        u8::try_from(status)
            .map_err(|_| ChainError::Decode(format!("note status {status} is out of range")))
    }
}

#[async_trait]
impl FeeConfigSource for BlokliChain {
    async fn fees(&self) -> Result<FeeConfig> {
        let response = self.gql(VAULT_FEES_QUERY, serde_json::json!({})).await?;
        let vault = union_node(&response, "curvyVaultFees")?;
        let aggregator = union_node(&response, "curvyAggregatorFees")?;
        let token_count = union_node(&response, "curvyVaultTokenCount")?;

        let fee_key = aggregator["feeNotePublicKey"]
            .as_array()
            .filter(|key| key.len() == 2)
            .ok_or_else(|| {
                ChainError::Decode(format!("feeNotePublicKey is not a pair: {aggregator}"))
            })?;
        let coordinate = |index: usize| -> Result<Dec> {
            fee_key[index].as_str().map(str::to_owned).ok_or_else(|| {
                ChainError::Decode(format!("feeNotePublicKey[{index}] is not a string"))
            })
        };

        // Skip deregistered token ids and propagate other errors.
        let count = uint256_u64(token_count, "count")?;
        let mut per_token_gas_fees = Vec::with_capacity(count as usize);
        for token_id in 1..=count {
            let token = self
                .gql(
                    VAULT_TOKEN_QUERY,
                    serde_json::json!({ "tokenId": token_id.to_string() }),
                )
                .await?;
            let node = match union_node(&token, "curvyVaultToken") {
                Ok(node) => node,
                Err(_) if is_not_found(&token, "curvyVaultToken") => continue,
                Err(error) => return Err(error),
            };
            let gas_fees = node.get("gasFees").ok_or_else(|| {
                ChainError::Decode(format!("curvyVaultToken has no gasFees: {node}"))
            })?;
            per_token_gas_fees.push(GasFees {
                token_id: string_field(gas_fees, "tokenId")?,
                portal_deployment: string_field(gas_fees, "portalDeployment")?,
                pending_note_commitment: string_field(gas_fees, "pendingNoteCommitment")?,
                withdrawal: string_field(gas_fees, "withdrawal")?,
            });
        }

        Ok(FeeConfig {
            deposit_fee_bps: uint256_u64(vault, "depositFee")?,
            withdrawal_fee_bps: uint256_u64(vault, "withdrawalFee")?,
            protocol_fee_per_thousand: string_field(aggregator, "protocolFeePerThousand")?,
            commitment_fee_root: hex32_field(aggregator, "commitmentFeeRoot")?,
            fee_note_public_key: [coordinate(0)?, coordinate(1)?],
            per_token_gas_fees,
        })
    }
}

#[async_trait]
impl BalanceReader for BlokliChain {
    async fn eth_balance(&self, address: &Addr) -> Result<Dec> {
        let response = self
            .gql(
                NATIVE_BALANCE_QUERY,
                serde_json::json!({ "address": address }),
            )
            .await?;
        let node = union_node(&response, "nativeBalance")?;
        token_value_to_wei(&string_field(node, "balance")?)
    }

    async fn erc20_balance(&self, token: &Addr, owner: &Addr) -> Result<Dec> {
        let response = self
            .gql(HOPR_BALANCE_QUERY, serde_json::json!({ "address": owner }))
            .await?;
        let chain_info = &response["data"]["chainInfo"];
        let encoded = chain_info["contractAddresses"].as_str().ok_or_else(|| {
            ChainError::Decode(format!("chainInfo has no contractAddresses: {chain_info}"))
        })?;
        let addresses: serde_json::Map<String, serde_json::Value> = serde_json::from_str(encoded)
            .map_err(|error| {
            ChainError::Decode(format!("invalid chainInfo contractAddresses: {error}"))
        })?;
        let configured = addresses
            .get("token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ChainError::Decode("chainInfo has no HOPR token address".to_string()))?;
        if !configured.eq_ignore_ascii_case(token) {
            return Err(ChainError::Unsupported(format!(
                "Blokli can only read its configured HOPR token {configured}, not {token}"
            )));
        }
        let node = union_node(&response, "hoprBalance")?;
        token_value_to_wei(&string_field(node, "balance")?)
    }

    async fn vault_balance(&self, _owner: &Addr, _token_id: &Dec) -> Result<Dec> {
        Err(ChainError::Unsupported(
            "blokli exposes no Curvy vault balanceOf read".to_string(),
        ))
    }

    async fn tx_count(&self, address: &Addr) -> Result<u64> {
        let response = self
            .gql(
                TRANSACTION_COUNT_QUERY,
                serde_json::json!({ "address": address }),
            )
            .await?;
        let node = union_node(&response, "transactionCount")?;
        u64_field(node, "count")
    }

    async fn gas_price(&self) -> Result<u128> {
        let response = self.gql(GAS_AND_CHAIN_QUERY, serde_json::json!({})).await?;
        let node = &response["data"]["chainInfo"];
        // Gas price is optional on the wire.
        node["gasPrice"]
            .as_str()
            .ok_or_else(|| {
                ChainError::Unsupported(
                    "chainInfo returned no gasPrice estimate; cannot price a legacy tx".to_string(),
                )
            })?
            .parse()
            .map_err(|error| ChainError::Decode(format!("invalid gasPrice: {error}")))
    }

    async fn chain_id(&self) -> Result<u64> {
        let response = self.gql(GAS_AND_CHAIN_QUERY, serde_json::json!({})).await?;
        u64_field(&response["data"]["chainInfo"], "chainId")
    }
}

#[async_trait]
impl PortalDirectory for BlokliChain {
    async fn entry_portal_address(&self, owner_hash: &Dec, recovery: &Addr) -> Result<Addr> {
        let response = self
            .gql(
                ENTRY_PORTAL_QUERY,
                serde_json::json!({ "ownerHash": owner_hash, "recovery": recovery }),
            )
            .await?;
        let node = union_node(&response, "curvyEntryPortalAddress")?;
        string_field(node, "address")
    }

    async fn portal_is_registered(&self, portal: &Addr) -> Result<bool> {
        let response = self
            .gql(
                PORTAL_REGISTERED_QUERY,
                serde_json::json!({ "portalAddress": portal }),
            )
            .await?;
        let node = union_node(&response, "curvyPortalRegistered")?;
        node["value"].as_bool().ok_or_else(|| {
            ChainError::Decode(format!("curvyPortalRegistered has no value: {node}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dec_to_hex32_round_trips_with_hex32_field() {
        let encoded = dec_to_hex32(&"16".to_string()).unwrap();
        assert_eq!(
            encoded,
            "0x0000000000000000000000000000000000000000000000000000000000000010"
        );
        let row = serde_json::json!({ "a": encoded });
        assert_eq!(hex32_field(&row, "a").unwrap(), "16");
    }

    #[test]
    fn dec_to_hex32_pads_to_the_scalar_width() {
        assert_eq!(dec_to_hex32(&"0".to_string()).unwrap().len(), 66);
    }

    #[test]
    fn dec_to_hex32_rejects_oversized_and_non_decimal() {
        let too_big = (BigUint::from(1u8) << 256u32).to_str_radix(10);
        assert!(dec_to_hex32(&too_big).is_err());
        assert!(dec_to_hex32(&"0xdeadbeef".to_string()).is_err());
    }

    #[test]
    fn token_value_rescales_to_exact_wei() {
        assert_eq!(token_value_to_wei("2 xDai").unwrap(), "2000000000000000000");
        assert_eq!(
            token_value_to_wei("2.5 xDai").unwrap(),
            "2500000000000000000"
        );
        assert_eq!(token_value_to_wei("0").unwrap(), "0");
    }

    #[test]
    fn token_value_keeps_single_wei_precision() {
        assert_eq!(
            token_value_to_wei("0.000000000000000001 xDai").unwrap(),
            "1"
        );
    }

    #[test]
    fn token_value_rejects_more_precision_than_the_currency_has() {
        assert!(token_value_to_wei("0.0000000000000000001 xDai").is_err());
        assert!(token_value_to_wei("").is_err());
    }
}
