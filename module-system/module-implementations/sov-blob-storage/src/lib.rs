#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod call;
pub use call::CallMessage;
mod capabilities;
#[cfg(feature = "native")]
mod query;

#[cfg(feature = "native")]
pub use query::*;
use sov_chain_state::TransitionHeight;
use sov_modules_api::{Module, ModuleInfo, StateMap, StateValue, WorkingSet};

/// For how many slots deferred blobs are stored before being executed
const DEFERRED_SLOTS_COUNT: u64 = 5;

/// Blob storage contains only address and vector of blobs
#[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
#[derive(Clone, ModuleInfo)]
pub struct BlobStorage<C: sov_modules_api::Context, Da: sov_modules_api::DaSpec> {
    /// The address of blob storage module
    /// Note: this is address is generated by the module framework and the corresponding private key is unknown.
    #[address]
    pub(crate) address: C::Address,

    /// Actual storage of blobs
    /// DA block number => vector of blobs
    /// Caller controls the order of blobs in the vector
    #[state]
    pub(crate) deferred_blobs: StateMap<u64, Vec<Vec<u8>>>,

    /// The number of deferred blobs which the preferred sequencer has asked to have executed during the next slot.
    /// This request will be honored unless:
    /// 1. More blobs have readched the maximum deferral period than the sequencer requests. In that case, all of those blobs will still be executed
    /// 2. The sequencer requests more blobs than are in the deferred queue. In that case, all of the blobs in the deferred queue will be executed.
    #[state]
    pub(crate) deferred_blobs_requested_for_execution_next_slot: StateValue<u16>,

    #[module]
    pub(crate) sequencer_registry: sov_sequencer_registry::SequencerRegistry<C, Da>,

    #[module]
    chain_state: sov_chain_state::ChainState<C, Da>,
}

/// Non standard methods for blob storage
impl<C: sov_modules_api::Context, Da: sov_modules_api::DaSpec> BlobStorage<C, Da> {
    /// Store blobs for given block number, overwrite if already exists
    pub fn store_blobs(
        &self,
        slot_height: TransitionHeight,
        blobs: &[&Da::BlobTransaction],
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let mut raw_blobs: Vec<Vec<u8>> = Vec::with_capacity(blobs.len());
        for blob in blobs {
            raw_blobs.push(bincode::serialize(blob)?);
        }
        self.deferred_blobs
            .set(&slot_height, &raw_blobs, working_set);
        Ok(())
    }

    /// Take all blobs for given block number, return empty vector if not exists
    /// Returned blobs are removed from the storage
    pub fn take_blobs_for_slot_height(
        &self,
        slot_height: TransitionHeight,
        working_set: &mut WorkingSet<C>,
    ) -> Vec<Da::BlobTransaction> {
        self.deferred_blobs
            .remove(&slot_height, working_set)
            .unwrap_or_default()
            .iter()
            .map(|b| bincode::deserialize(b).expect("malformed blob was stored previously"))
            .collect()
    }

    pub(crate) fn get_preferred_sequencer(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> Option<Da::Address> {
        self.sequencer_registry.get_preferred_sequencer(working_set)
    }

    pub(crate) fn get_current_slot_height(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> TransitionHeight {
        self.chain_state.get_slot_height(working_set)
    }

    pub(crate) fn get_deferred_slots_count(&self, _working_set: &mut WorkingSet<C>) -> u64 {
        DEFERRED_SLOTS_COUNT
    }
}

/// Empty module implementation
impl<C: sov_modules_api::Context, Da: sov_modules_api::DaSpec> Module for BlobStorage<C, Da> {
    type Context = C;
    type Config = ();
    type CallMessage = CallMessage;

    fn genesis(
        &self,
        _config: &Self::Config,
        _working_set: &mut WorkingSet<Self::Context>,
    ) -> Result<(), sov_modules_api::Error> {
        Ok(())
    }

    fn call(
        &self,
        message: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> Result<sov_modules_api::CallResponse, sov_modules_api::Error> {
        match message {
            CallMessage::ProcessDeferredBlobsEarly { number } => {
                self.handle_process_blobs_early_msg(context, number, working_set);
                Ok(Default::default())
            }
        }
    }
}
