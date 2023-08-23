mod test_helpers;
use std::net::SocketAddr;

use borsh::BorshSerialize;
use demo_stf::app::DefaultPrivateKey;
use demo_stf::runtime::RuntimeCall;
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{PrivateKey, Spec};
use sov_sequencer::utils::SimpleClient;
use test_helpers::start_rollup;

const TOKEN_SALT: u64 = 0;
const TOKEN_NAME: &str = "test_token";

async fn send_test_create_token_tx(rpc_address: SocketAddr) -> Result<(), anyhow::Error> {
    let key = DefaultPrivateKey::generate();
    let user_address: <DefaultContext as Spec>::Address = key.to_address();

    let token_address = sov_bank::get_token_address::<DefaultContext>(
        TOKEN_NAME,
        user_address.as_ref(),
        TOKEN_SALT,
    );

    let msg = RuntimeCall::bank(sov_bank::CallMessage::<DefaultContext>::CreateToken {
        salt: TOKEN_SALT,
        token_name: TOKEN_NAME.to_string(),
        initial_balance: 1000,
        minter_address: user_address,
        authorized_minters: vec![],
    });
    let tx = Transaction::<DefaultContext>::new_signed_tx(&key, msg.try_to_vec().unwrap(), 0);

    let port = rpc_address.port();
    let http_client = SimpleClient::new(&format!("http://localhost:{}", port));
    let ws_client = WsClientBuilder::default()
        .build(&format!("ws://localhost:{}", port))
        .await?;

    let mut slot_processed_subscription: Subscription<u64> = ws_client
        .subscribe(
            "ledger_subscribeSlots",
            rpc_params![],
            "ledger_unsubscribeSlots",
        )
        .await?;

    http_client.send_transaction(tx).await?;

    // Wait until the rollup has processed the next slot
    let _ = slot_processed_subscription.next().await;

    let balance_response = sov_bank::query::BankRpcClient::<DefaultContext>::balance_of(
        http_client.inner(),
        user_address,
        token_address,
    )
    .await?;
    assert_eq!(balance_response.amount.unwrap_or_default(), 1000);
    Ok(())
}

#[tokio::test]
async fn bank_tx_tests() -> Result<(), anyhow::Error> {
    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_task = tokio::spawn(async {
        start_rollup(port_tx).await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    send_test_create_token_tx(port).await?;
    rollup_task.abort();
    Ok(())
}
