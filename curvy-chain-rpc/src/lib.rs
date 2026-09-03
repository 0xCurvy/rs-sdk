//! Direct-RPC Curvy adapters built with alloy.

use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use async_trait::async_trait;
use curvy_abi::bindings::{
    aggregator::CurvyAggregatorAlphaV2, erc20::IERC20, portal_factory::PortalFactory,
    vault::CurvyVaultV2,
};
use curvy_chain_api::{
    BalanceReader, ChainError, FeeConfigSource, NoteIndexSource, PortalDirectory, Result,
    RootAnchor, TxSubmitter,
};
use curvy_types::{
    Addr, AggregatorState, CommittedNotesEvent, CommittedNullifiersEvent, Dec, FeeConfig, GasFees,
    PendingNotesEvent, RawTx, TxOutcome,
};

fn transport<E: std::fmt::Display>(e: E) -> ChainError {
    ChainError::Transport(e.to_string())
}
fn addr(a: &str) -> Result<Address> {
    a.parse()
        .map_err(|e| ChainError::Decode(format!("bad address {a:?}: {e}")))
}
fn u256(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| ChainError::Decode(format!("bad uint {s:?}: {e}")))
}
fn u256_u64(value: U256, name: &str) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| ChainError::Decode(format!("{name} does not fit u64: {value}")))
}

/// Direct-RPC chain client.
#[derive(Clone)]
pub struct RpcChain {
    provider: DynProvider,
    aggregator: Address,
    vault: Address,
    portal_factory: Address,
}

impl RpcChain {
    pub fn new(rpc_url: &str, aggregator: &str, vault: &str, portal_factory: &str) -> Result<Self> {
        let url = rpc_url
            .parse()
            .map_err(|e| ChainError::Transport(format!("bad rpc url {rpc_url:?}: {e}")))?;
        let provider = ProviderBuilder::new().connect_http(url).erased();
        Ok(Self {
            provider,
            aggregator: addr(aggregator)?,
            vault: addr(vault)?,
            portal_factory: addr(portal_factory)?,
        })
    }

    fn agg(&self) -> CurvyAggregatorAlphaV2::CurvyAggregatorAlphaV2Instance<&DynProvider> {
        CurvyAggregatorAlphaV2::new(self.aggregator, &self.provider)
    }
    fn vlt(&self) -> CurvyVaultV2::CurvyVaultV2Instance<&DynProvider> {
        CurvyVaultV2::new(self.vault, &self.provider)
    }
    fn factory(&self) -> PortalFactory::PortalFactoryInstance<&DynProvider> {
        PortalFactory::new(self.portal_factory, &self.provider)
    }

    async fn logs(
        &self,
        topic0: alloy::primitives::B256,
        from: u64,
        to: u64,
    ) -> Result<Vec<alloy::rpc::types::Log>> {
        let filter = Filter::new()
            .address(self.aggregator)
            .event_signature(topic0)
            .from_block(from)
            .to_block(to);
        self.provider.get_logs(&filter).await.map_err(transport)
    }
}

#[async_trait]
impl NoteIndexSource for RpcChain {
    async fn pending_notes(&self, from: u64, to: u64) -> Result<Vec<PendingNotesEvent>> {
        self.logs(curvy_abi::topics::pending_notes(), from, to)
            .await?
            .iter()
            .map(|l| {
                curvy_abi::decode_pending_notes(l).map_err(|e| ChainError::Decode(e.to_string()))
            })
            .collect()
    }
    async fn committed_notes(&self, from: u64, to: u64) -> Result<Vec<CommittedNotesEvent>> {
        self.logs(curvy_abi::topics::committed_notes(), from, to)
            .await?
            .iter()
            .map(|l| {
                curvy_abi::decode_committed_notes(l).map_err(|e| ChainError::Decode(e.to_string()))
            })
            .collect()
    }
    async fn committed_nullifiers(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<CommittedNullifiersEvent>> {
        self.logs(curvy_abi::topics::committed_nullifiers(), from, to)
            .await?
            .iter()
            .map(|l| {
                curvy_abi::decode_committed_nullifiers(l)
                    .map_err(|e| ChainError::Decode(e.to_string()))
            })
            .collect()
    }
    async fn head_block(&self) -> Result<u64> {
        self.provider.get_block_number().await.map_err(transport)
    }
}

#[async_trait]
impl RootAnchor for RpcChain {
    async fn state(&self) -> Result<AggregatorState> {
        let a = self.agg();
        Ok(AggregatorState {
            current_notes_root: a
                .currentNotesTreeRoot()
                .call()
                .await
                .map_err(transport)?
                .to_string(),
            current_note_index: u256_u64(
                a.currentNoteIndex().call().await.map_err(transport)?,
                "currentNoteIndex",
            )?,
            current_notes_batch_index: u256_u64(
                a.currentNotesBatchIndex().call().await.map_err(transport)?,
                "currentNotesBatchIndex",
            )?,
            current_nullifiers_batch_index: u256_u64(
                a.currentNullifiersBatchIndex()
                    .call()
                    .await
                    .map_err(transport)?,
                "currentNullifiersBatchIndex",
            )?,
        })
    }
    async fn is_valid_notes_root(&self, root: &Dec) -> Result<bool> {
        self.agg()
            .validNotesRoot(u256(root)?)
            .call()
            .await
            .map_err(transport)
    }
    async fn note_status(&self, note_id: &Dec) -> Result<u8> {
        Ok(self
            .agg()
            .noteStatus(u256(note_id)?)
            .call()
            .await
            .map_err(transport)?)
    }
}

#[async_trait]
impl FeeConfigSource for RpcChain {
    async fn fees(&self) -> Result<FeeConfig> {
        let a = self.agg();
        let v = self.vlt();

        let deposit_fee = v.depositFee().call().await.map_err(transport)?;
        let deposit_fee_bps = deposit_fee.try_into().map_err(|_| {
            ChainError::Decode(format!("depositFee does not fit u64: {deposit_fee}"))
        })?;
        let withdrawal_fee = v.withdrawalFee().call().await.map_err(transport)?;
        let withdrawal_fee_bps = withdrawal_fee.try_into().map_err(|_| {
            ChainError::Decode(format!("withdrawalFee does not fit u64: {withdrawal_fee}"))
        })?;
        let protocol_fee = a.protocolFeePerThousand().call().await.map_err(transport)?;
        let commitment_fee_root = a.commitmentFeeRoot().call().await.map_err(transport)?;
        let fee_pk_x = a
            .feeNotePublicKey(U256::from(0))
            .call()
            .await
            .map_err(transport)?;
        let fee_pk_y = a
            .feeNotePublicKey(U256::from(1))
            .call()
            .await
            .map_err(transport)?;

        let num_tokens = u256_u64(
            v.getNumberOfTokens().call().await.map_err(transport)?,
            "getNumberOfTokens",
        )?;
        let mut per_token_gas_fees = Vec::new();
        for tid in 1..=num_tokens {
            let g = v
                .perTokenGasFees(U256::from(tid))
                .call()
                .await
                .map_err(transport)?;
            per_token_gas_fees.push(GasFees {
                token_id: tid.to_string(),
                portal_deployment: g.portalDeployment.to_string(),
                pending_note_commitment: g.pendingNoteCommitment.to_string(),
                withdrawal: g.withdrawal.to_string(),
            });
        }

        Ok(FeeConfig {
            deposit_fee_bps,
            withdrawal_fee_bps,
            protocol_fee_per_thousand: protocol_fee.to_string(),
            commitment_fee_root: commitment_fee_root.to_string(),
            fee_note_public_key: [fee_pk_x.to_string(), fee_pk_y.to_string()],
            per_token_gas_fees,
        })
    }
}

#[async_trait]
impl BalanceReader for RpcChain {
    async fn eth_balance(&self, a: &Addr) -> Result<Dec> {
        Ok(self
            .provider
            .get_balance(addr(a)?)
            .await
            .map_err(transport)?
            .to_string())
    }
    async fn erc20_balance(&self, token: &Addr, owner: &Addr) -> Result<Dec> {
        Ok(IERC20::new(addr(token)?, self.provider.clone())
            .balanceOf(addr(owner)?)
            .call()
            .await
            .map_err(transport)?
            .to_string())
    }
    async fn vault_balance(&self, owner: &Addr, token_id: &Dec) -> Result<Dec> {
        Ok(self
            .vlt()
            .balanceOf(addr(owner)?, u256(token_id)?)
            .call()
            .await
            .map_err(transport)?
            .to_string())
    }
    async fn tx_count(&self, a: &Addr) -> Result<u64> {
        self.provider
            .get_transaction_count(addr(a)?)
            .await
            .map_err(transport)
    }
    async fn gas_price(&self) -> Result<u128> {
        self.provider.get_gas_price().await.map_err(transport)
    }
    async fn chain_id(&self) -> Result<u64> {
        self.provider.get_chain_id().await.map_err(transport)
    }
}

#[async_trait]
impl PortalDirectory for RpcChain {
    async fn entry_portal_address(&self, owner_hash: &Dec, recovery: &Addr) -> Result<Addr> {
        Ok(self
            .factory()
            .getEntryPortalAddress(u256(owner_hash)?, addr(recovery)?)
            .call()
            .await
            .map_err(transport)?
            .to_string())
    }
    async fn portal_is_registered(&self, portal: &Addr) -> Result<bool> {
        self.factory()
            .portalIsRegistered(addr(portal)?)
            .call()
            .await
            .map_err(transport)
    }
}

/// Submit with `eth_sendRawTransaction` and await its receipt.
#[async_trait]
impl TxSubmitter for RpcChain {
    async fn submit(&self, raw: &RawTx) -> Result<TxOutcome> {
        let pending = self
            .provider
            .send_raw_transaction(&raw.0)
            .await
            .map_err(|error| ChainError::Ambiguous(error.to_string()))?;
        let receipt = pending.get_receipt().await.map_err(transport)?;
        let tx_hash = receipt.transaction_hash.to_string();
        if !receipt.status() {
            return Err(ChainError::Reverted { tx_hash });
        }
        Ok(TxOutcome {
            tx_hash,
            block_number: receipt.block_number,
            status: true,
        })
    }
    fn backend(&self) -> &'static str {
        "rpc-direct"
    }
}
