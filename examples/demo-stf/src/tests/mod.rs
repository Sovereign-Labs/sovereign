use borsh::BorshSerialize;
use sov_modules_api::{
    default_context::DefaultContext, default_signature::private_key::DefaultPrivateKey, Address,
};
use sov_modules_stf_template::{AppTemplate, Batch, SequencerOutcome, TxEffect};
use sov_rollup_interface::stf::BatchReceipt;
use sov_state::ProverStorage;
use std::path::Path;

use crate::{
    app::DemoApp,
    genesis_config::{
        create_demo_genesis_config, generate_address, DEMO_SEQUENCER_DA_ADDRESS,
        DEMO_SEQ_PUB_KEY_STR,
    },
    runtime::{GenesisConfig, Runtime},
};

mod data_generation;
mod stf_tests;
mod tx_revert_tests;
pub(crate) type C = DefaultContext;

pub type TestBlob = sov_rollup_interface::mocks::TestBlob<Address>;

pub fn new_test_blob(batch: Batch, address: &[u8]) -> TestBlob {
    let address = Address::try_from(address).unwrap();
    let data = batch.try_to_vec().unwrap();
    TestBlob::new(data, address)
}

pub fn create_new_demo(
    path: impl AsRef<Path>,
) -> DemoApp<DefaultContext, sov_rollup_interface::mocks::MockZkvm> {
    let runtime = Runtime::default();
    let storage = ProverStorage::with_path(path).unwrap();
    AppTemplate::new(storage, runtime)
}

pub fn create_demo_config(
    initial_sequencer_balance: u64,
    value_setter_admin_private_key: &DefaultPrivateKey,
    election_admin_private_key: &DefaultPrivateKey,
) -> GenesisConfig<DefaultContext> {
    create_demo_genesis_config::<DefaultContext>(
        initial_sequencer_balance,
        generate_address::<DefaultContext>(DEMO_SEQ_PUB_KEY_STR),
        DEMO_SEQUENCER_DA_ADDRESS.to_vec(),
        value_setter_admin_private_key,
        election_admin_private_key,
    )
}

pub fn has_tx_events(apply_blob_outcome: &BatchReceipt<SequencerOutcome, TxEffect>) -> bool {
    let events = apply_blob_outcome
        .tx_receipts
        .iter()
        .flat_map(|receipts| receipts.events.iter());

    events.peekable().peek().is_some()
}
