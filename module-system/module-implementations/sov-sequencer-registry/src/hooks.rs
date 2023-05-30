use crate::Sequencer;

use sov_modules_api::{
    hooks::{ApplyBlobTxHooks, Transaction},
    Context, Spec,
};
use sov_state::WorkingSet;

impl<C: Context> ApplyBlobTxHooks for Sequencer<C> {
    type Context = C;

    fn pre_dispatch_tx_hook(
        &self,
        _tx: Transaction<C>,
        _working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> anyhow::Result<<Self::Context as Spec>::Address> {
        todo!()
    }

    fn post_dispatch_tx_hook(
        &self,
        _tx: &Transaction<Self::Context>,
        _working_set: &mut WorkingSet<<Self::Context as sov_modules_api::Spec>::Storage>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn enter_apply_blob(
        &self,
        sequencer_da: &[u8],
        working_set: &mut WorkingSet<<Self::Context as sov_modules_api::Spec>::Storage>,
    ) -> anyhow::Result<()> {
        let next_sequencer_da = self.seq_da_address.get_or_err(working_set);

        match next_sequencer_da {
            Ok(next_sequencer_da) => {
                if next_sequencer_da != sequencer_da {
                    anyhow::bail!("Invalid next sequencer.")
                }
            }
            Err(_) => anyhow::bail!("Sequencer {:?} not registered. ", sequencer_da),
        }

        let sequencer = &self.seq_rollup_address.get_or_err(working_set)?;
        let locker = &self.address;
        let coins = self.coins_to_lock.get_or_err(working_set)?;

        self.bank
            .transfer_from(sequencer, locker, coins, working_set)?;

        Ok(())
    }

    fn exit_apply_blob(
        &self,
        _amount: u64,
        working_set: &mut WorkingSet<<Self::Context as sov_modules_api::Spec>::Storage>,
    ) -> anyhow::Result<()> {
        let sequencer = &self.seq_rollup_address.get_or_err(working_set)?;
        let locker = &self.address;
        let coins = self.coins_to_lock.get_or_err(working_set)?;

        self.bank
            .transfer_from(locker, sequencer, coins, working_set)?;

        Ok(())
    }
}
