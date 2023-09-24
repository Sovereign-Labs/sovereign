#[cfg(feature = "experimental")]
pub mod call;
#[cfg(feature = "experimental")]
pub mod evm;
#[cfg(feature = "experimental")]
pub mod genesis;
#[cfg(feature = "experimental")]
pub mod hooks;
#[cfg(feature = "native")]
#[cfg(feature = "experimental")]
mod query;
#[cfg(feature = "native")]
#[cfg(feature = "experimental")]
pub use query::*;
#[cfg(feature = "experimental")]
pub mod signer;
#[cfg(feature = "smart_contracts")]
pub mod smart_contracts;
#[cfg(feature = "experimental")]
#[cfg(test)]
mod tests;
#[cfg(feature = "experimental")]
pub use experimental::{AccountData, Evm, EvmConfig};
#[cfg(feature = "experimental")]
pub use revm::primitives::SpecId;

#[cfg(feature = "experimental")]
mod experimental {
    use std::collections::HashMap;

    use reth_primitives::{Address, Bytes, H256};
    use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
    use sov_modules_api::{Error, ModuleInfo, WorkingSet};
    use sov_state::codec::BcsCodec;

    use super::evm::db::EvmDb;
    use super::evm::{DbAccount, EvmChainConfig};
    use crate::evm::primitive_types::{
        Block, BlockEnv, Receipt, SealedBlock, TransactionSignedAndRecovered,
    };
    #[derive(Clone, Debug)]
    pub struct AccountData {
        pub address: Address,
        pub balance: U256,
        pub code_hash: H256,
        pub code: Bytes,
        pub nonce: u64,
    }

    impl AccountData {
        pub fn empty_code() -> H256 {
            KECCAK_EMPTY
        }

        pub fn balance(balance: u64) -> U256 {
            U256::from(balance)
        }
    }

    #[derive(Clone, Debug)]
    pub struct EvmConfig {
        pub data: Vec<AccountData>,
        pub chain_id: u64,
        pub limit_contract_code_size: Option<usize>,
        pub spec: HashMap<u64, SpecId>,
        pub coinbase: Address,
        pub starting_base_fee: u64,
        pub block_gas_limit: u64,
        pub genesis_timestamp: u64,
        pub block_timestamp_delta: u64,
        pub base_fee_params: reth_primitives::BaseFeeParams,
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub(crate) struct PendingTransaction {
        pub(crate) transaction: TransactionSignedAndRecovered,
        pub(crate) receipt: Receipt,
    }

    impl Default for EvmConfig {
        fn default() -> Self {
            Self {
                data: vec![],
                chain_id: 1,
                limit_contract_code_size: None,
                spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
                coinbase: Address::zero(),
                starting_base_fee: reth_primitives::constants::MIN_PROTOCOL_BASE_FEE,
                block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
                block_timestamp_delta: reth_primitives::constants::SLOT_DURATION.as_secs(),
                genesis_timestamp: 0,
                base_fee_params: reth_primitives::BaseFeeParams::ethereum(),
            }
        }
    }

    /// TODO
    #[allow(dead_code)]
    // #[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
    #[derive(ModuleInfo, Clone)]
    pub struct Evm<C: sov_modules_api::Context> {
        /// The address of the evm module.
        #[address]
        pub(crate) address: C::Address,

        /// Mapping from account address to account state.
        #[state]
        pub(crate) accounts: sov_modules_api::StateMap<Address, DbAccount, BcsCodec>,

        /// Mapping from code hash to code. Used for lazy-loading code into a contract account.
        #[state]
        pub(crate) code:
            sov_modules_api::StateMap<reth_primitives::H256, reth_primitives::Bytes, BcsCodec>,

        /// Chain configuration. This field is set in genesis.
        #[state]
        pub(crate) cfg: sov_modules_api::StateValue<EvmChainConfig, BcsCodec>,

        /// Block environment used by the evm. This field is set in `begin_slot_hook`.
        #[state]
        pub(crate) block_env: sov_modules_api::StateValue<BlockEnv, BcsCodec>,

        /// Transactions that will be added to the current block.
        /// A valid transaction is added to the vec on every call message.
        #[state]
        pub(crate) pending_transactions: sov_modules_api::StateVec<PendingTransaction, BcsCodec>,

        /// Head of the chain. The new head is set in `end_slot_hook` but without the inclusion of the `state_root` field.
        /// The `state_root` is added in `begin_slot_hook` of the next block because its calculation occurs after the `end_slot_hook`.
        #[state]
        pub(crate) head: sov_modules_api::StateValue<Block, BcsCodec>,

        /// Used only by the RPC: This represents the head of the chain and is set in two distinct stages:
        /// 1. `end_slot_hook`: the pending head is populated with data from pending_transactions.
        /// 2. `finalize_slot_hook` the `root_hash` is populated.
        /// Since this value is not authenticated, it can be modified in the `finalize_slot_hook` with the correct `state_root`.
        #[state]
        pub(crate) pending_head: sov_modules_api::AccessoryStateValue<Block, BcsCodec>,

        /// Used only by the RPC: The vec is extended with `pending_head` in `finalize_slot_hook`.
        #[state]
        pub(crate) blocks: sov_modules_api::AccessoryStateVec<SealedBlock, BcsCodec>,

        /// Used only by the RPC: block_hash => block_number mapping,
        #[state]
        pub(crate) block_hashes:
            sov_modules_api::AccessoryStateMap<reth_primitives::H256, u64, BcsCodec>,

        /// Used only by the RPC: List of processed transactions.
        #[state]
        pub(crate) transactions:
            sov_modules_api::AccessoryStateVec<TransactionSignedAndRecovered, BcsCodec>,

        /// Used only by the RPC: transaction_hash => transaction_index mapping.
        #[state]
        pub(crate) transaction_hashes:
            sov_modules_api::AccessoryStateMap<reth_primitives::H256, u64, BcsCodec>,

        /// Used only by the RPC: Receipts.
        #[state]
        pub(crate) receipts: sov_modules_api::AccessoryStateVec<Receipt, BcsCodec>,
    }

    impl<C: sov_modules_api::Context> sov_modules_api::Module for Evm<C> {
        type Context = C;

        type Config = EvmConfig;

        type CallMessage = super::call::CallMessage;

        fn genesis(
            &self,
            config: &Self::Config,
            working_set: &mut WorkingSet<C>,
        ) -> Result<(), Error> {
            Ok(self.init_module(config, working_set)?)
        }

        fn call(
            &self,
            msg: Self::CallMessage,
            context: &Self::Context,
            working_set: &mut WorkingSet<C>,
        ) -> Result<sov_modules_api::CallResponse, Error> {
            Ok(self.execute_call(msg.tx, context, working_set)?)
        }
    }

    impl<C: sov_modules_api::Context> Evm<C> {
        pub(crate) fn get_db<'a>(&self, working_set: &'a mut WorkingSet<C>) -> EvmDb<'a, C> {
            EvmDb::new(self.accounts.clone(), self.code.clone(), working_set)
        }
    }
}
