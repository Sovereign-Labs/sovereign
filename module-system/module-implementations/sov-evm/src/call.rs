use crate::{
    evm::{
        db::EvmDb,
        executor::{self},
        transaction::EvmTransaction,
    },
    Evm,
};
use anyhow::Result;
use revm::primitives::CfgEnv;
use sov_modules_api::CallResponse;
use sov_state::WorkingSet;

#[cfg_attr(
    feature = "native",
    derive(serde::Serialize),
    derive(serde::Deserialize)
)]
#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq, Clone)]
pub struct CallMessage {
    pub tx: EvmTransaction,
}

impl<C: sov_modules_api::Context> Evm<C> {
    pub(crate) fn execute_call(
        &self,
        tx: EvmTransaction,
        _context: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<CallResponse> {
        let cfg_env = CfgEnv::default();
        let block_env = self.block_env.get(working_set).unwrap_or_default();
        let evm_db: EvmDb<'_, C> = self.get_db(working_set);

        // It is ok to use the unwrap here because the error type is `Infallible`.
        executor::execute_tx(evm_db, block_env, tx, cfg_env).unwrap();
        Ok(CallResponse::default())
    }
}
