use std::str::FromStr;

use clap::Parser;
use demo_stf::genesis_config::GenesisPaths;
use sov_demo_rollup::{new_rollup_with_celestia_da, new_rollup_with_mock_da};
use sov_risc0_adapter::host::Risc0Host;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

const DEMO_GENESIS_PATHS: GenesisPaths<&str> = GenesisPaths {
    bank_genesis_path: "../test-data/genesis/demo-tests/bank.json",
    sequencer_genesis_path: "../test-data/genesis/demo-tests/sequencer_registry.json",
    value_setter_genesis_path: "../test-data/genesis/demo-tests/value_setter.json",
    accounts_genesis_path: "../test-data/genesis/demo-tests/accounts.json",
    chain_state_genesis_path: "../test-data/genesis/demo-tests/chain_state.json",
    nft_path: "../test-data/genesis/demo-tests/nft.json",
    #[cfg(feature = "experimental")]
    evm_genesis_path: "../test-data/genesis/demo-tests/evm.json",
};

const TEST_GENESIS_PATHS: GenesisPaths<&str> = GenesisPaths {
    bank_genesis_path: "../test-data/genesis/integration-tests/bank.json",
    sequencer_genesis_path: "../test-data/genesis/integration-tests/sequencer_registry.json",
    value_setter_genesis_path: "../test-data/genesis/integration-tests/value_setter.json",
    accounts_genesis_path: "../test-data/genesis/integration-tests/accounts.json",
    chain_state_genesis_path: "../test-data/genesis/integration-tests/chain_state.json",
    nft_path: "../test-data/genesis/integration-tests/nft.json",
    #[cfg(feature = "experimental")]
    evm_genesis_path: "../test-data/genesis/integration-tests/evm.json",
};

#[cfg(test)]
mod test_rpc;

/// Main demo runner. Initialize a DA chain, and starts a demo-rollup using the config provided
/// (or a default config if not provided). Then start checking the blocks sent to the DA layer in
/// the main event loop.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The data layer type.
    #[arg(long, default_value = "celestia")]
    da_layer: String,

    /// The path to the rollup config.
    #[arg(long, default_value = "rollup_config.toml")]
    rollup_config_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Initializing logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_str("debug,hyper=info").unwrap())
        .init();

    let args = Args::parse();
    let rollup_config_path = args.rollup_config_path.as_str();

    match args.da_layer.as_str() {
        "mock" => {
            let rollup = new_rollup_with_mock_da::<Risc0Host<'static>, _>(
                rollup_config_path,
                None,
                &TEST_GENESIS_PATHS,
            )?;
            rollup.run().await
        }
        "celestia" => {
            let rollup = new_rollup_with_celestia_da::<Risc0Host<'static>, _>(
                rollup_config_path,
                None,
                &DEMO_GENESIS_PATHS,
            )
            .await?;
            rollup.run().await
        }
        da => panic!("DA Layer not supported: {}", da),
    }
}
