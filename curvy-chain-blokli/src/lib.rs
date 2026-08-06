//! Blokli GraphQL adapters for transaction submission and note indexing.
//!
//! ## Schema
//! Curvy queries return unions, use `Hex32` identifiers and paginate by an exclusive
//! chain-position cursor.

pub mod chain;

use async_trait::async_trait;
use curvy_chain_api::{ChainError, NoteIndexSource, Result, TxSubmitter};
use curvy_types::{
    CommittedNotesEvent, CommittedNullifiersEvent, Dec, NotesTreeSnapshot, PendingNotesEvent,
    RawTx, TxOutcome,
};

const SYNC_MUTATION: &str = r#"
mutation ($raw: String!, $c: Int) {
  sendTransactionSync(input: { rawTransaction: $raw }, confirmations: $c) {
    __typename
    ... on Transaction { id status transactionHash submittedAt }
    ... on RpcError { code message }
    ... on TimeoutError { code message }
    ... on ContractNotAllowedError { code message }
    ... on FunctionNotAllowedError { code message }
  }
}"#;

const CHAININFO_QUERY: &str = r#"
query { chainInfo { __typename ... on ChainInfo { blockNumber chainId network finality } } }"#;

const PENDING_NOTES_QUERY: &str = r#"
query ($fromBlock: UInt64, $after: CurvyEventCursor, $first: Int!) {
  curvyPendingNotes(fromBlock: $fromBlock, after: $after, first: $first) {
    __typename
    ... on CurvyPendingNotes {
      notes {
        noteId ephemeralKey viewTag tokenId amount isPlaintext
        position { block transactionIndex logIndex eventItemIndex transactionHash }
      }
    }
    ... on QueryFailedError { code message }
  }
}"#;

const COMMITTED_NOTES_QUERY: &str = r#"
query ($fromBlock: UInt64, $after: CurvyEventCursor, $first: Int!) {
  curvyCommittedNotes(fromBlock: $fromBlock, after: $after, first: $first) {
    __typename
    ... on CurvyCommittedNotes {
      notes {
        noteId batchIndex leafIndex
        position { block transactionIndex logIndex eventItemIndex transactionHash }
      }
    }
    ... on QueryFailedError { code message }
  }
}"#;

const COMMITTED_NULLIFIERS_QUERY: &str = r#"
query ($fromBlock: UInt64, $after: CurvyEventCursor, $first: Int!) {
  curvyCommittedNullifiers(fromBlock: $fromBlock, after: $after, first: $first) {
    __typename
    ... on CurvyCommittedNullifiers {
      nullifiers {
        nullifier batchIndex nullifierIndex
        position { block transactionIndex logIndex eventItemIndex transactionHash }
      }
    }
    ... on QueryFailedError { code message }
  }
}"#;

const SYNC_CHECKPOINT_QUERY: &str = r#"
query {
  curvySyncCheckpoint {
    __typename
    ... on CurvySyncCheckpoint { blockHash blockNumber noteCount notesRoot treeDepth }
    ... on QueryFailedError { code message }
  }
}"#;

const SYNC_NOTES_QUERY: &str = r#"
query ($checkpoint: Hex32!, $fromIndex: UInt64, $first: Int!) {
  curvySyncNotes(checkpoint: $checkpoint, fromIndex: $fromIndex, first: $first) {
    __typename
    ... on CurvySyncNotePage {
      checkpoint
      notes { leafIndex noteId }
      nextIndex
      total
    }
    ... on QueryFailedError { code message }
  }
}"#;

/// blokli rejects `first` above this, so it is also the natural page size.
const CURVY_EVENT_PAGE_SIZE: i64 = 1000;

/// Refuse to spin forever if the server ever stops advancing the cursor.
const MAX_PAGES: usize = 10_000;

/// A blokli GraphQL client. Point it at the bloklid base URL (default
/// `http://127.0.0.1:8080`).
pub struct BlokliChain {
    client: reqwest::Client,
    base: String,
    confirmations: i64,
}

/// One event's canonical chain position - also the shape of the `after` cursor.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Position {
    block: u64,
    transaction_index: u64,
    log_index: u64,
    event_item_index: u64,
    transaction_hash: String,
}

impl Position {
    /// The exclusive cursor blokli expects for the next page.
    fn to_cursor(&self) -> serde_json::Value {
        serde_json::json!({
            "block": self.block.to_string(),
            "transactionIndex": self.transaction_index.to_string(),
            "logIndex": self.log_index.to_string(),
            "eventItemIndex": self.event_item_index.to_string(),
        })
    }

    /// Rows sharing everything but `eventItemIndex` came from one on-chain event.
    fn same_event(&self, other: &Position) -> bool {
        self.block == other.block
            && self.transaction_index == other.transaction_index
            && self.log_index == other.log_index
    }
}

impl BlokliChain {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            base: base.into(),
            confirmations: 1,
        }
    }

    async fn gql(&self, query: &str, variables: serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}/graphql", self.base))
            .json(&serde_json::json!({ "query": query, "variables": variables }))
            .send()
            .await
            .map_err(|e| ChainError::Transport(format!("graphql POST: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ChainError::Transport(format!("graphql decode: {e}")))?;
        if let Some(errors) = body.get("errors").filter(|errors| !errors.is_null()) {
            return Err(ChainError::Rejected(format!(
                "GraphQL error: {errors}. Note that this adapter targets the \
                 curvy-events-finalized schema"
            )));
        }
        Ok(body)
    }

    /// Readiness probe: `GET /readyz` reports `"status":"ready"`.
    pub async fn is_ready(&self) -> bool {
        match self
            .client
            .get(format!("{}/readyz", self.base))
            .send()
            .await
        {
            Ok(r) => r
                .text()
                .await
                .map(|b| b.contains("\"status\":\"ready\""))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// `chainInfo` - `(network, chainId)` - used by the e2e readiness ledger.
    pub async fn chain_info(&self) -> Result<(String, u64)> {
        let v = self.gql(CHAININFO_QUERY, serde_json::json!({})).await?;
        let node = &v["data"]["chainInfo"];
        let network = string_field(node, "network")?;
        let chain_id = u64_field(node, "chainId")?;
        Ok((network, chain_id))
    }

    /// Follow the `after` cursor to exhaustion.
    async fn paged_rows(
        &self,
        query: &str,
        root_field: &str,
        list_field: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(Position, serde_json::Value)>> {
        let mut cursor: Option<serde_json::Value> = None;
        let mut out: Vec<(Position, serde_json::Value)> = Vec::new();

        for _ in 0..MAX_PAGES {
            let response = self
                .gql(
                    query,
                    serde_json::json!({
                        "fromBlock": from_block.to_string(),
                        "after": cursor,
                        "first": CURVY_EVENT_PAGE_SIZE,
                    }),
                )
                .await?;
            let node = union_node(&response, root_field)?;
            let rows = node
                .get(list_field)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    ChainError::Decode(format!("missing {root_field}.{list_field}: {node}"))
                })?;
            let page_len = rows.len();
            for row in rows {
                let position = position(row)?;
                // Enforce the upper block bound locally.
                if position.block > to_block {
                    return Ok(out);
                }
                cursor = Some(position.to_cursor());
                out.push((position, row.clone()));
            }
            if page_len < CURVY_EVENT_PAGE_SIZE as usize {
                return Ok(out);
            }
        }
        Err(ChainError::Decode(format!(
            "{root_field}: cursor did not terminate after {MAX_PAGES} pages"
        )))
    }
}

// Field decoding.

/// Append a leaf at its declared position.
fn push_dense_leaf(leaves: &mut Vec<Dec>, leaf_index: u64, note_id: Dec) -> Result<()> {
    if leaf_index != leaves.len() as u64 {
        return Err(ChainError::Decode(format!(
            "curvySyncNotes returned leaf {leaf_index} where {} was expected",
            leaves.len()
        )));
    }
    leaves.push(note_id);
    Ok(())
}

/// Test whether a union response reports `NOT_FOUND`.
pub(crate) fn is_not_found(response: &serde_json::Value, field: &str) -> bool {
    response["data"][field]["code"].as_str() == Some("NOT_FOUND")
}

pub(crate) fn union_node<'a>(
    response: &'a serde_json::Value,
    field: &str,
) -> Result<&'a serde_json::Value> {
    let node = &response["data"][field];
    match node["__typename"].as_str() {
        Some("QueryFailedError") | Some("InvalidAddressError") => {
            let code = node["code"].as_str().unwrap_or("");
            let message = node["message"].as_str().unwrap_or("(no message)");
            Err(ChainError::Rejected(format!(
                "{field} failed: {code} {message}"
            )))
        }
        None => Err(ChainError::Decode(format!(
            "unexpected {field} result: {node}"
        ))),
        Some(_) => Ok(node),
    }
}

pub(crate) fn string_field(value: &serde_json::Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ChainError::Decode(format!("missing string field {name}: {value}")))
}

fn u64_field(value: &serde_json::Value, name: &str) -> Result<u64> {
    let field = value
        .get(name)
        .ok_or_else(|| ChainError::Decode(format!("missing field {name}: {value}")))?;
    if let Some(number) = field.as_u64() {
        return Ok(number);
    }
    field
        .as_str()
        .ok_or_else(|| {
            ChainError::Decode(format!("field {name} is not an unsigned integer: {field}"))
        })?
        .parse()
        .map_err(|error| ChainError::Decode(format!("invalid {name}: {error}")))
}

/// Decode `Hex32` as a canonical decimal value.
fn hex32_field(value: &serde_json::Value, name: &str) -> Result<Dec> {
    let raw = string_field(value, name)?;
    let digits = raw.strip_prefix("0x").unwrap_or(&raw);
    if digits.is_empty() || digits.len() > 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ChainError::Decode(format!(
            "field {name} is not a 32-byte hexadecimal value: {raw:?}"
        )));
    }
    num_bigint::BigUint::parse_bytes(digits.as_bytes(), 16)
        .map(|value| value.to_str_radix(10))
        .ok_or_else(|| ChainError::Decode(format!("field {name} is not a Hex32 value: {raw:?}")))
}

/// A `Hex32` batch index as the `u64` the SDK's event types carry.
fn hex32_u64_field(value: &serde_json::Value, name: &str) -> Result<u64> {
    hex32_field(value, name)?
        .parse()
        .map_err(|error| ChainError::Decode(format!("{name} does not fit u64: {error}")))
}

fn position(value: &serde_json::Value) -> Result<Position> {
    let value = value
        .get("position")
        .ok_or_else(|| ChainError::Decode(format!("missing event position: {value}")))?;
    Ok(Position {
        block: u64_field(value, "block")?,
        transaction_index: u64_field(value, "transactionIndex")?,
        log_index: u64_field(value, "logIndex")?,
        event_item_index: u64_field(value, "eventItemIndex")?,
        transaction_hash: string_field(value, "transactionHash")?,
    })
}

#[async_trait]
impl NoteIndexSource for BlokliChain {
    async fn pending_notes(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<PendingNotesEvent>> {
        let rows = self
            .paged_rows(
                PENDING_NOTES_QUERY,
                "curvyPendingNotes",
                "notes",
                from_block,
                to_block,
            )
            .await?;

        let mut events = Vec::<PendingNotesEvent>::new();
        let mut last: Option<Position> = None;
        for (position, row) in rows {
            if last.as_ref().is_none_or(|prev| !prev.same_event(&position)) {
                events.push(PendingNotesEvent {
                    block_number: position.block,
                    tx_hash: position.transaction_hash.clone(),
                    ..Default::default()
                });
            }
            last = Some(position);
            let event = events
                .last_mut()
                .ok_or_else(|| ChainError::Decode("missing pending accumulator".to_string()))?;

            let ephemeral_key = row
                .get("ephemeralKey")
                .and_then(serde_json::Value::as_array)
                .filter(|key| key.len() == 2)
                .ok_or_else(|| ChainError::Decode(format!("invalid ephemeralKey: {row}")))?;
            event.note_ids.push(hex32_field(&row, "noteId")?);
            event.ephemeral_keys[0].push(
                ephemeral_key[0]
                    .as_str()
                    .ok_or_else(|| ChainError::Decode(format!("invalid ephemeralKey x: {row}")))?
                    .to_string(),
            );
            event.ephemeral_keys[1].push(
                ephemeral_key[1]
                    .as_str()
                    .ok_or_else(|| ChainError::Decode(format!("invalid ephemeralKey y: {row}")))?
                    .to_string(),
            );
            event.view_tags.push(u64_field(&row, "viewTag")?);
            event.tokens.push(string_field(&row, "tokenId")?);
            event.amounts.push(string_field(&row, "amount")?);
            event.is_plaintext.push(
                row.get("isPlaintext")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| ChainError::Decode(format!("invalid isPlaintext: {row}")))?,
            );
        }
        Ok(events)
    }

    async fn committed_notes(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<CommittedNotesEvent>> {
        let rows = self
            .paged_rows(
                COMMITTED_NOTES_QUERY,
                "curvyCommittedNotes",
                "notes",
                from_block,
                to_block,
            )
            .await?;

        let mut events = Vec::<CommittedNotesEvent>::new();
        let mut last: Option<(Position, u64)> = None;
        for (position, row) in rows {
            let batch_index = hex32_u64_field(&row, "batchIndex")?;
            let is_new = last
                .as_ref()
                .is_none_or(|(prev, batch)| !prev.same_event(&position) || *batch != batch_index);
            if is_new {
                events.push(CommittedNotesEvent {
                    batch_index,
                    block_number: position.block,
                    ..Default::default()
                });
            }
            last = Some((position, batch_index));
            events
                .last_mut()
                .ok_or_else(|| {
                    ChainError::Decode("missing committed-note accumulator".to_string())
                })?
                .note_ids
                .push(hex32_field(&row, "noteId")?);
        }
        Ok(events)
    }

    async fn committed_nullifiers(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<CommittedNullifiersEvent>> {
        let rows = self
            .paged_rows(
                COMMITTED_NULLIFIERS_QUERY,
                "curvyCommittedNullifiers",
                "nullifiers",
                from_block,
                to_block,
            )
            .await?;

        let mut events = Vec::<CommittedNullifiersEvent>::new();
        let mut last: Option<(Position, u64)> = None;
        for (position, row) in rows {
            let batch_index = hex32_u64_field(&row, "batchIndex")?;
            let is_new = last
                .as_ref()
                .is_none_or(|(prev, batch)| !prev.same_event(&position) || *batch != batch_index);
            if is_new {
                events.push(CommittedNullifiersEvent {
                    batch_index,
                    block_number: position.block,
                    ..Default::default()
                });
            }
            last = Some((position, batch_index));
            events
                .last_mut()
                .ok_or_else(|| {
                    ChainError::Decode("missing committed-nullifier accumulator".to_string())
                })?
                .nullifiers
                .push(hex32_field(&row, "nullifier")?);
        }
        Ok(events)
    }

    async fn head_block(&self) -> Result<u64> {
        let response = self.gql(CHAININFO_QUERY, serde_json::json!({})).await?;
        u64_field(&response["data"]["chainInfo"], "blockNumber")
    }

    async fn notes_tree_snapshot(&self) -> Result<Option<NotesTreeSnapshot>> {
        // Only `NOT_FOUND` selects the event-log fallback.
        let response = self
            .gql(SYNC_CHECKPOINT_QUERY, serde_json::json!({}))
            .await?;
        let checkpoint_node = match union_node(&response, "curvySyncCheckpoint") {
            Ok(node) => node,
            Err(_) if is_not_found(&response, "curvySyncCheckpoint") => return Ok(None),
            Err(error) => return Err(error),
        };
        let checkpoint = string_field(checkpoint_node, "blockHash")?;
        let notes_root = hex32_field(checkpoint_node, "notesRoot")?;
        let total = u64_field(checkpoint_node, "noteCount")?;
        let tree_depth = u64_field(checkpoint_node, "treeDepth")?;
        if tree_depth != 30 || total > (1u64 << tree_depth) {
            return Err(ChainError::Decode(format!(
                "invalid Curvy checkpoint shape: depth {tree_depth}, {total} notes"
            )));
        }

        // Grow storage only as validated pages arrive.
        let mut leaves: Vec<Dec> = Vec::new();
        while (leaves.len() as u64) < total {
            let page = self
                .gql(
                    SYNC_NOTES_QUERY,
                    serde_json::json!({
                        "checkpoint": checkpoint,
                        "fromIndex": leaves.len().to_string(),
                        "first": CURVY_EVENT_PAGE_SIZE,
                    }),
                )
                .await?;
            let node = union_node(&page, "curvySyncNotes")?;
            if string_field(node, "checkpoint")? != checkpoint {
                return Err(ChainError::Decode(
                    "curvySyncNotes changed checkpoint mid-snapshot".to_string(),
                ));
            }
            if u64_field(node, "total")? != total {
                return Err(ChainError::Decode(
                    "curvySyncNotes changed total mid-snapshot".to_string(),
                ));
            }
            let rows = node
                .get("notes")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    ChainError::Decode(format!("missing curvySyncNotes.notes: {node}"))
                })?;
            if rows.is_empty() {
                return Err(ChainError::Decode(format!(
                    "curvySyncNotes stalled at leaf {} of {total}",
                    leaves.len()
                )));
            }
            for row in rows {
                if leaves.len() as u64 >= total {
                    return Err(ChainError::Decode(format!(
                        "curvySyncNotes returned more than checkpoint total {total}"
                    )));
                }
                push_dense_leaf(
                    &mut leaves,
                    u64_field(row, "leafIndex")?,
                    hex32_field(row, "noteId")?,
                )?;
            }
        }

        Ok(Some(NotesTreeSnapshot {
            checkpoint,
            notes_root,
            leaves,
        }))
    }
}

#[async_trait]
impl TxSubmitter for BlokliChain {
    async fn submit(&self, raw: &RawTx) -> Result<TxOutcome> {
        let res = self
            .gql(
                SYNC_MUTATION,
                serde_json::json!({ "raw": raw.to_hex(), "c": self.confirmations }),
            )
            .await?;

        sync_transaction_outcome(&res["data"]["sendTransactionSync"])
    }

    fn backend(&self) -> &'static str {
        "blokli"
    }
}

fn sync_transaction_outcome(node: &serde_json::Value) -> Result<TxOutcome> {
    match node["__typename"].as_str() {
        Some("Transaction") => {
            let tx_hash = node["transactionHash"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            // Accept only explicit success statuses.
            let status = node["status"].as_str().unwrap_or_default();
            if !status.eq_ignore_ascii_case("CONFIRMED")
                && !status.eq_ignore_ascii_case("MINED")
                && !status.eq_ignore_ascii_case("SUCCESS")
            {
                if status.eq_ignore_ascii_case("FAILED") || status.eq_ignore_ascii_case("REVERTED")
                {
                    return Err(ChainError::Reverted { tx_hash });
                }
                return Err(ChainError::Ambiguous(format!(
                    "sendTransactionSync returned status {status:?} for {tx_hash}"
                )));
            }
            Ok(TxOutcome {
                tx_hash,
                block_number: None,
                status: true,
            })
        }
        Some("TimeoutError") => {
            let msg = node["message"].as_str().unwrap_or("(no message)");
            Err(ChainError::Ambiguous(format!(
                "sendTransactionSync timed out: {msg}"
            )))
        }
        Some(other) => {
            let msg = node["message"].as_str().unwrap_or("(no message)");
            let code = node["code"].as_str().unwrap_or("");
            Err(ChainError::Rejected(format!("{other} {code}: {msg}")))
        }
        None => Err(ChainError::Decode(format!(
            "unexpected sendTransactionSync result: {node}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only `NOT_FOUND` means no snapshot exists.
    #[test]
    fn only_a_missing_checkpoint_reads_as_no_snapshot() {
        let absent = serde_json::json!({
            "data": { "curvySyncCheckpoint": {
                "__typename": "QueryFailedError",
                "code": "NOT_FOUND",
                "message": "Curvy sync checkpoint not found: latest",
            }}
        });
        assert!(is_not_found(&absent, "curvySyncCheckpoint"));

        for code in ["QUERY_FAILED", "CONTEXT_ERROR"] {
            let broken = serde_json::json!({
                "data": { "curvySyncCheckpoint": {
                    "__typename": "QueryFailedError",
                    "code": code,
                    "message": "database is on fire",
                }}
            });
            assert!(
                !is_not_found(&broken, "curvySyncCheckpoint"),
                "{code} is an outage, not an empty chain"
            );
            assert!(union_node(&broken, "curvySyncCheckpoint").is_err());
        }
    }

    #[test]
    fn a_checkpoint_response_without_a_code_is_not_treated_as_absent() {
        let malformed = serde_json::json!({ "data": { "curvySyncCheckpoint": null } });
        assert!(!is_not_found(&malformed, "curvySyncCheckpoint"));
    }

    #[test]
    fn a_sync_timeout_is_ambiguous_not_rejected() {
        let node = serde_json::json!({
            "__typename": "TimeoutError",
            "code": "TIMEOUT",
            "message": "receipt wait expired",
        });
        assert!(matches!(
            sync_transaction_outcome(&node),
            Err(ChainError::Ambiguous(_))
        ));
    }

    #[test]
    fn a_failed_transaction_is_a_confirmed_revert() {
        let node = serde_json::json!({
            "__typename": "Transaction",
            "transactionHash": "0x1234",
            "status": "REVERTED",
        });
        assert!(matches!(
            sync_transaction_outcome(&node),
            Err(ChainError::Reverted { tx_hash }) if tx_hash == "0x1234"
        ));
    }

    #[test]
    fn hex32_decodes_to_canonical_decimal() {
        let row = serde_json::json!({
            "a": "0x0000000000000000000000000000000000000000000000000000000000000010",
            "b": "0000000000000000000000000000000000000000000000000000000000000000",
        });
        assert_eq!(hex32_field(&row, "a").unwrap(), "16");
        assert_eq!(hex32_field(&row, "b").unwrap(), "0");
    }

    #[test]
    fn hex32_rejects_non_hex() {
        let row = serde_json::json!({ "a": "not-hex" });
        assert!(hex32_field(&row, "a").is_err());
    }

    #[test]
    fn hex32_rejects_values_wider_than_32_bytes() {
        let row = serde_json::json!({ "a": format!("0x1{}", "0".repeat(64)) });
        assert!(hex32_field(&row, "a").is_err());
    }

    #[test]
    fn rows_of_one_event_differ_only_by_item_index() {
        let base = Position {
            block: 7,
            transaction_index: 1,
            log_index: 2,
            event_item_index: 0,
            transaction_hash: "0xabc".into(),
        };
        let sibling = Position {
            event_item_index: 1,
            ..base.clone()
        };
        let next_log = Position {
            log_index: 3,
            ..base.clone()
        };
        assert!(base.same_event(&sibling));
        assert!(!base.same_event(&next_log));
    }

    #[test]
    fn dense_leaves_append_in_order() {
        let mut leaves = Vec::new();
        push_dense_leaf(&mut leaves, 0, "11".into()).unwrap();
        push_dense_leaf(&mut leaves, 1, "22".into()).unwrap();
        assert_eq!(leaves, vec!["11".to_string(), "22".to_string()]);
    }

    #[test]
    fn a_gap_or_repeat_in_leaf_indices_is_rejected() {
        let mut skipped = vec!["11".to_string()];
        assert!(push_dense_leaf(&mut skipped, 2, "33".into()).is_err());

        let mut repeated = vec!["11".to_string(), "22".to_string()];
        assert!(push_dense_leaf(&mut repeated, 1, "33".into()).is_err());
    }

    #[test]
    fn cursor_uses_string_encoded_positions() {
        let cursor = Position {
            block: 12,
            transaction_index: 0,
            log_index: 4,
            event_item_index: 3,
            transaction_hash: "0xabc".into(),
        }
        .to_cursor();
        assert_eq!(cursor["block"], "12");
        assert_eq!(cursor["eventItemIndex"], "3");
    }
}
