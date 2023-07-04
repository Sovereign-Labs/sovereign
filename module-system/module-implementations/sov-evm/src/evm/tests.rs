use super::{db::EvmDb, db_init::InitEvmDb, executor};
use crate::{
    evm::{
        test_helpers::{contract_address, output, test_data_path},
        transaction::{BlockEnv, EvmTransaction},
        AccountInfo,
    },
    Evm,
};

use ethers_contract::BaseContract;
use ethers_core::abi::Abi;
use revm::{
    db::CacheDB,
    primitives::{CfgEnv, KECCAK_EMPTY, U256},
    Database, DatabaseCommit,
};
use sov_state::{ProverStorage, WorkingSet};
use std::{convert::Infallible, path::PathBuf};

type C = sov_modules_api::default_context::DefaultContext;

fn make_contract_from_abi(path: PathBuf) -> BaseContract {
    let abi_json = std::fs::read_to_string(path).unwrap();
    let abi: Abi = serde_json::from_str(&abi_json).unwrap();
    BaseContract::from(abi)
}

#[test]
fn simple_contract_execution_sov_state() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set: WorkingSet<<C as sov_modules_api::Spec>::Storage> =
        WorkingSet::new(ProverStorage::with_path(tmpdir.path()).unwrap());

    let evm = Evm::<C>::default();
    let evm_db: EvmDb<'_, C> = evm.get_db(&mut working_set);

    simple_contract_execution(evm_db);
}

#[test]
fn simple_contract_execution_in_memory_state() {
    let db = CacheDB::default();
    simple_contract_execution(db);
}

fn simple_contract_execution<DB: Database<Error = Infallible> + DatabaseCommit + InitEvmDb>(
    mut evm_db: DB,
) {
    let caller: [u8; 20] = [11; 20];
    evm_db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(1000000000).to_le_bytes(),
            code_hash: KECCAK_EMPTY.to_fixed_bytes(),
            code: vec![],
            nonce: 1,
        },
    );

    let contract_address = {
        let mut path = test_data_path();
        path.push("SimpleStorage.bin");

        let contract_data = std::fs::read_to_string(path).unwrap();
        let contract_data = hex::decode(contract_data).unwrap();

        let tx = EvmTransaction {
            to: None,
            data: contract_data,
            ..Default::default()
        };

        let result =
            executor::execute_tx(&mut evm_db, BlockEnv::default(), tx, CfgEnv::default()).unwrap();
        contract_address(result)
    };

    let set_arg = ethereum_types::U256::from(21989);

    let mut path = test_data_path();
    path.push("SimpleStorage.abi");

    let contract = make_contract_from_abi(path);

    {
        let call_data = contract.encode("set", set_arg).unwrap();

        let tx = EvmTransaction {
            to: Some(*contract_address.as_fixed_bytes()),
            data: hex::decode(hex::encode(&call_data)).unwrap(),
            nonce: 1,
            ..Default::default()
        };

        executor::execute_tx(&mut evm_db, BlockEnv::default(), tx, CfgEnv::default()).unwrap();
    }

    let get_res = {
        let call_data = contract.encode("get", ()).unwrap();

        let tx = EvmTransaction {
            to: Some(*contract_address.as_fixed_bytes()),
            data: hex::decode(hex::encode(&call_data)).unwrap(),
            nonce: 2,
            ..Default::default()
        };

        let result =
            executor::execute_tx(&mut evm_db, BlockEnv::default(), tx, CfgEnv::default()).unwrap();

        let out = output(result);
        ethereum_types::U256::from(out.as_ref())
    };

    assert_eq!(set_arg, get_res)
}
