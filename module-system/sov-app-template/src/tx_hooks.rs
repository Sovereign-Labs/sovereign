use anyhow::Result;
use sov_modules_api::{Context, Spec};
use sov_state::WorkingSet;

/// Represents a transaction after verification.
pub trait VerifiedTx {
    type Address;
    fn sender(&self) -> &Self::Address;
    fn runtime_message(&self) -> &[u8];
}

/// TxHooks allows injecting custom logic into a transaction processing pipeline.
pub trait TxHooks {
    type Context: Context;
    type Transaction;
    type VerifiedTx: VerifiedTx<Address = <Self::Context as Spec>::Address>;

    /// runs just before a transaction is dispatched to an appropriate module.
    fn pre_dispatch_tx_hook(
        &self,
        tx: Self::Transaction,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> anyhow::Result<Self::VerifiedTx>;

    /// runs after the tx is dispatched to an appropriate module.
    fn post_dispatch_tx_hook(
        &self,
        tx: Self::VerifiedTx,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    );

    /// runs at the beginning of apply_blob.
    fn enter_apply_blob(
        &self,
        sequencer: &[u8],
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<()>;

    /// runs at the end of apply_batch.
    fn exit_apply_blob(
        &self,
        amount: u64,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<()>;
}
