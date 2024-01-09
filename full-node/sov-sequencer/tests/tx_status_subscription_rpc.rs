use borsh::BorshSerialize;
use demo_stf::runtime::Runtime;
use sov_data_generators::bank_data::BankMessageGenerator;
use sov_data_generators::MessageGenerator;
use sov_mock_da::{MockBlockHeader, MockDaService, MockDaSpec};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::digest::Digest;
use sov_modules_api::Spec;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::services::batch_builder::TxHash;
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_sequencer::batch_builder::FiFoStrictBatchBuilder;
use sov_sequencer::utils::SimpleClient;
use sov_sequencer::{Sequencer, TxStatus};
use sov_state::DefaultStorageSpec;
use tempfile::TempDir;

fn new_sequencer(
    dir: &TempDir,
) -> Sequencer<
    FiFoStrictBatchBuilder<DefaultContext, Runtime<DefaultContext, MockDaSpec>>,
    MockDaService,
> {
    let sequencer_addr = [42u8; 32];
    let runtime = Runtime::<DefaultContext, MockDaSpec>::default();

    let storage_config = sov_state::config::Config {
        path: dir.path().to_path_buf(),
    };
    let mut storage_manager =
        ProverStorageManager::<MockDaSpec, DefaultStorageSpec>::new(storage_config).unwrap();
    let genesis_block_header = MockBlockHeader::from_height(0);
    let storage = storage_manager
        .create_storage_on(&genesis_block_header)
        .expect("Getting genesis storage failed");

    let da_service = MockDaService::new(sequencer_addr.into());
    let batch_builder = sov_sequencer::batch_builder::FiFoStrictBatchBuilder::new(
        usize::MAX,
        usize::MAX,
        runtime,
        storage,
        sequencer_addr.into(),
    );

    Sequencer::new(batch_builder, da_service)
}

#[tokio::test]
async fn subscribe() {
    let temp_dir = TempDir::new().expect("Unable to create temporary directory");
    let sequencer = new_sequencer(&temp_dir);

    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_rpc_module = sequencer.rpc();
    let _server_handle = server.start(server_rpc_module);

    let client = SimpleClient::new("127.0.0.1", addr.port()).await.unwrap();

    let bank_generator = BankMessageGenerator::<DefaultContext>::default();
    let mut messages_iter = bank_generator.create_messages().into_iter().peekable();
    let mut txs = Vec::default();
    while let Some(message) = messages_iter.next() {
        let is_last = messages_iter.peek().is_none();

        let tx = bank_generator.create_tx::<Runtime<DefaultContext, MockDaSpec>>(
            &message.sender_key,
            message.content,
            message.chain_id,
            message.gas_tip,
            message.gas_limit,
            message.nonce,
            is_last,
        );

        txs.push(tx);
    }

    let tx_hash: TxHash =
        <DefaultContext as Spec>::Hasher::digest(txs[0].try_to_vec().unwrap()).into();
    let mut subscription = client
        .subscribe_to_tx_status_updates::<()>(tx_hash)
        .await
        .unwrap();

    let tx_status = subscription.next().await.unwrap().unwrap();
    assert_eq!(tx_status, TxStatus::Unknown);

    client.send_transactions(txs, None).await.unwrap();

    let tx_status = subscription.next().await.unwrap().unwrap();
    assert!(matches!(
        tx_status,
        TxStatus::Submitted | TxStatus::Published { .. }
    ));
    let tx_status = subscription.next().await.unwrap().unwrap();
    assert!(matches!(tx_status, TxStatus::Published { .. }));

    subscription.unsubscribe().await.unwrap();
}
