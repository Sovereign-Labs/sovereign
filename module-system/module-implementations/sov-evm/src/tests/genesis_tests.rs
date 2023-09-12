use lazy_static::lazy_static;
use reth_primitives::constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS, ETHEREUM_BLOCK_GAS_LIMIT};
use reth_primitives::hex_literal::hex;
use reth_primitives::{Address, Bloom, Bytes, Header, SealedHeader, EMPTY_OMMER_ROOT, H256};
use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::Module;
use sov_state::{DefaultStorageSpec, ProverStorage, WorkingSet};

use crate::evm::transaction::Block;
// use crate::evm::db;
use crate::{evm::EvmChainConfig, AccountData, Evm, EvmConfig};
type C = DefaultContext;

lazy_static! {
    pub(crate) static ref TEST_CONFIG: EvmConfig = EvmConfig {
        data: vec![AccountData {
            address: Address::from([1u8; 20]),
            balance: U256::from(1000000000),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
        }],
        spec: vec![(0, SpecId::BERLIN), (1, SpecId::LATEST)]
            .into_iter()
            .collect(),
        chain_id: 1000,
        block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
        block_timestamp_delta: 2,
        genesis_timestamp: 50,
        coinbase: Address::from([3u8; 20]),
        limit_contract_code_size: Some(5000),
        starting_base_fee: 70,
    };
}

#[test]
fn genesis_data() {
    get_evm(&TEST_CONFIG);

    // TODO: assert on account being the same - easier after unifying stored types!
    // let db_account = evm.accounts.get(&address, working_set).unwrap();
}

#[test]
fn genesis_cfg() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let cfg = evm.cfg.get(&mut working_set).unwrap();
    assert_eq!(
        cfg,
        EvmChainConfig {
            spec: vec![(0, SpecId::BERLIN), (1, SpecId::LATEST)],
            chain_id: 1000,
            block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
            block_timestamp_delta: 2,
            coinbase: Address::from([3u8; 20]),
            limit_contract_code_size: Some(5000)
        }
    );
}

#[test]
#[should_panic(expected = "EVM spec must start from block 0")]
fn genesis_cfg_missing_specs() {
    get_evm(&EvmConfig {
        spec: vec![(5, SpecId::BERLIN)].into_iter().collect(),
        ..Default::default()
    });
}

#[test]
fn genesis_block() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let block = evm
        .blocks
        .get(0usize, &mut working_set.accessory_state())
        .unwrap();

    assert_eq!(
        block,
        Block {
            header: SealedHeader {
                header: Header {
                    parent_hash: H256::default(),
                    state_root: KECCAK_EMPTY,
                    transactions_root: EMPTY_TRANSACTIONS,
                    receipts_root: EMPTY_RECEIPTS,
                    logs_bloom: Bloom::default(),
                    difficulty: U256::ZERO,
                    number: 0,
                    gas_limit: ETHEREUM_BLOCK_GAS_LIMIT,
                    gas_used: 0,
                    timestamp: 50,
                    extra_data: Bytes::default(),
                    mix_hash: H256::default(),
                    nonce: 0,
                    base_fee_per_gas: Some(70),
                    ommers_hash: EMPTY_OMMER_ROOT,
                    beneficiary: Address::from([3u8; 20]),
                    withdrawals_root: None
                },
                hash: H256(hex!(
                    "d57423e4375c45bc114cd137146aab671dbd3f6304f05b31bdd416301b4a99f0"
                ))
            },
            transactions: (0u64..0u64),
        }
    );
}

pub(crate) fn get_evm(
    config: &EvmConfig,
) -> (Evm<C>, WorkingSet<ProverStorage<DefaultStorageSpec>>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set = WorkingSet::new(ProverStorage::with_path(tmpdir.path()).unwrap());
    let evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set).unwrap();

    (evm, working_set)
}
