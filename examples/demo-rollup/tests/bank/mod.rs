use std::net::SocketAddr;

use borsh::BorshSerialize;
use demo_stf::genesis_config::GenesisPaths;
use demo_stf::runtime::RuntimeCall;
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::rpc_params;
use sov_mock_da::{MockAddress, MockDaConfig, MockDaSpec};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{PrivateKey, Spec};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_sequencer::utils::SimpleClient;
use sov_stf_runner::RollupProverConfig;

use crate::test_helpers::start_rollup;

const TOKEN_SALT: u64 = 0;
const TOKEN_NAME: &str = "test_token";

#[tokio::test]
async fn bank_tx_tests_instant_finality() -> Result<(), anyhow::Error> {
    bank_tx_tests(0).await
}

#[tokio::test]
async fn bank_tx_tests_non_instant_finality() -> Result<(), anyhow::Error> {
    bank_tx_tests(3).await
}

async fn bank_tx_tests(finalization_blocks: u32) -> anyhow::Result<()> {
    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_task = tokio::spawn(async move {
        start_rollup(
            port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Skip,
            MockDaConfig {
                sender_address: MockAddress::new([11; 32]),
                finalization_blocks,
                wait_attempts: 10,
            },
        )
        .await;
    });

    let port = port_rx.await.unwrap();

    // If the rollup throws an error, return it and stop trying to send the transaction
    tokio::select! {
        err = rollup_task => err?,
        res = send_test_create_token_tx(port) => res?,
    };
    Ok(())
}

async fn send_test_create_token_tx(rpc_address: SocketAddr) -> Result<(), anyhow::Error> {
    let key = DefaultPrivateKey::generate();
    let user_address: <DefaultContext as Spec>::Address = key.to_address();

    let token_address = sov_bank::get_token_address::<DefaultContext>(
        TOKEN_NAME,
        user_address.as_ref(),
        TOKEN_SALT,
    );

    let msg = RuntimeCall::<DefaultContext, MockDaSpec>::bank(sov_bank::CallMessage::<
        DefaultContext,
    >::CreateToken {
        salt: TOKEN_SALT,
        token_name: TOKEN_NAME.to_string(),
        initial_balance: 1000,
        minter_address: user_address,
        authorized_minters: vec![],
    });
    let chain_id = 0;
    let gas_tip = 0;
    let gas_limit = 0;
    let nonce = 0;
    let tx = Transaction::<DefaultContext>::new_signed_tx(
        &key,
        msg.try_to_vec().unwrap(),
        chain_id,
        gas_tip,
        gas_limit,
        nonce,
    );

    let port = rpc_address.port();
    let client = SimpleClient::new("localhost", port).await?;

    let mut slot_processed_subscription: Subscription<u64> = client
        .ws()
        .subscribe(
            "ledger_subscribeSlots",
            rpc_params![],
            "ledger_unsubscribeSlots",
        )
        .await?;

    client.send_transaction(tx).await?;

    // Wait until the rollup has processed the next slot
    let _ = slot_processed_subscription.next().await;

    let balance_response = sov_bank::BankRpcClient::<DefaultContext>::balance_of(
        client.http(),
        user_address,
        token_address,
    )
    .await?;
    assert_eq!(balance_response.amount.unwrap_or_default(), 1000);
    Ok(())
}
