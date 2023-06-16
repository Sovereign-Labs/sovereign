use super::{db::EvmDb, executor};
use bytes::Bytes;
use ethereum_types::U256 as EU256;
use ethers_contract::BaseContract;
use ethers_core::abi::Abi;
use revm::{
    db::CacheDB,
    primitives::{
        AccountInfo, ExecutionResult, Output, TransactTo, TxEnv, B160, KECCAK_EMPTY, U256,
    },
};
use std::{path::PathBuf, str::FromStr};

fn output(result: ExecutionResult) -> Bytes {
    match result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(out) => out,
            Output::Create(out, _) => out,
        },
        _ => panic!("Expected successful ExecutionResult"),
    }
}

fn contract_address(result: ExecutionResult) -> B160 {
    match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(addr)),
            ..
        } => addr,
        _ => panic!("Expected successful contract creation"),
    }
}

fn test_data_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src");
    path.push("evm");
    path.push("test_data");
    path
}

fn make_contract_from_abi(path: PathBuf) -> BaseContract {
    let abi_json = std::fs::read_to_string(path).unwrap();
    let abi: Abi = serde_json::from_str(&abi_json).unwrap();
    BaseContract::from(abi)
}

#[test]
fn simple_contract_execution() {
    let caller = B160::from_str("0x1000000000000000000000000000000000000000").unwrap();
    let mut db = CacheDB::default();

    db.insert_account_info(
        caller,
        AccountInfo {
            nonce: 1,
            balance: U256::from(1000000000),
            code: None,
            code_hash: KECCAK_EMPTY,
        },
    );

    let contract_address = {
        let mut path = test_data_path();
        path.push("SimpleStorage.bin");

        let contract_data = std::fs::read_to_string(path).unwrap();
        let contract_data = Bytes::from(hex::decode(contract_data).unwrap());

        let tx_env = TxEnv {
            transact_to: TransactTo::create(),
            data: contract_data,
            ..Default::default()
        };

        let result = executor::execute_tx(EvmDb { db: &mut db }, tx_env).unwrap();
        contract_address(result)
    };

    let set_arg = EU256::from(21989);

    let mut path = test_data_path();
    path.push("SimpleStorage.abi");

    let contract = make_contract_from_abi(path);

    {
        let call_data = contract.encode("set", set_arg).unwrap();

        let tx_env = TxEnv {
            transact_to: TransactTo::Call(contract_address),
            data: Bytes::from(hex::decode(hex::encode(&call_data)).unwrap()),
            ..Default::default()
        };

        executor::execute_tx(EvmDb { db: &mut db }, tx_env).unwrap();
    }

    let get_res = {
        let call_data = contract.encode("get", ()).unwrap();

        let tx_env = TxEnv {
            transact_to: TransactTo::Call(contract_address),
            data: Bytes::from(hex::decode(hex::encode(&call_data)).unwrap()),
            ..Default::default()
        };

        let result = executor::execute_tx(EvmDb { db: &mut db }, tx_env).unwrap();

        let out = output(result);
        EU256::from(out.as_ref())
    };

    assert_eq!(set_arg, get_res)
}
