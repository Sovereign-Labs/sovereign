use ethers_core::types::Block;
use revm::primitives::{CfgEnv, SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::{Context, Module, PrivateKey, Spec};
use sov_state::{ProverStorage, WorkingSet};

use crate::call::CallMessage;
use crate::evm::test_helpers::SimpleStorageContract;
use crate::evm::transaction::{BlockEnv, EvmTransaction};
use crate::evm::EthAddress;
use crate::{AccountData, Evm, EvmConfig};

type C = DefaultContext;

fn create_messages(contract_addr: EthAddress, set_arg: u32) -> Vec<CallMessage> {
    let mut transactions = Vec::default();
    let contract = SimpleStorageContract::new();

    // Contract creation.
    {
        transactions.push(CallMessage {
            tx: EvmTransaction {
                to: None,
                data: contract.byte_code().to_vec(),
                ..Default::default()
            },
        });
    }

    // Update contract state.
    {
        transactions.push(CallMessage {
            tx: EvmTransaction {
                to: Some(contract_addr),
                data: hex::decode(hex::encode(&contract.set_call_data(set_arg))).unwrap(),
                nonce: 1,
                ..Default::default()
            },
        });
    }

    transactions
}

#[test]
fn evm_test() {
    use sov_modules_api::PublicKey;
    let tmpdir = tempfile::tempdir().unwrap();
    let working_set = &mut WorkingSet::new(ProverStorage::with_path(tmpdir.path()).unwrap());

    let priv_key = DefaultPrivateKey::generate();

    let sender = priv_key.pub_key();
    let sender_addr = sender.to_address::<<C as Spec>::Address>();
    let sender_context = C::new(sender_addr);
    let caller = [0; 20];

    let evm = Evm::<C>::default();

    let data = AccountData {
        address: caller,
        balance: U256::from(1000000000).to_le_bytes(),
        code_hash: KECCAK_EMPTY.to_fixed_bytes(),
        code: vec![],
        nonce: 0,
    };

    let config = EvmConfig {
        data: vec![data],
        spec: vec![(0, SpecIdWrapper::new(SpecId::LATEST))]
            .into_iter()
            .collect(),
        ..Default::default()
    };

    evm.genesis(&config, working_set).unwrap();

    let contract_addr = hex::decode("bd770416a3345f91e4b34576cb804a576fa48eb1")
        .unwrap()
        .try_into()
        .unwrap();

    let set_arg = 999;

    for tx in create_messages(contract_addr, set_arg) {
        evm.call(tx, &sender_context, working_set).unwrap();
    }

    let db_account = evm.accounts.get(&contract_addr, working_set).unwrap();
    let storage_key = &[0; 32];
    let storage_value = db_account.storage.get(storage_key, working_set).unwrap();

    assert_eq!(set_arg.to_le_bytes(), storage_value[0..4])
}

#[test]
fn cfg_test() {
    let evm = Evm::<C>::default();
    let block_env = BlockEnv {
        number: 10,
        ..Default::default()
    };

    let cfg = EvmChainCfg {
        chain_id: 1,
        limit_contract_code_size: Some(100),
        spec: vec![(0, SpecIdWrapper::new(SpecId::SHANGHAI))]
            .into_iter()
            .collect(),
    };

    let template_cfg = CfgEnv {
        chain_id: U256::from(2),
        disable_base_fee: true,
        ..Default::default()
    };

    let cfg_env = evm.get_cfg_env(&block_env, cfg, Some(template_cfg));

    assert_eq!(
        cfg_env,
        CfgEnv {
            chain_id: U256::from(1),
            disable_base_fee: true,
            spec_id: SpecIdWrapper::new(SpecId::SHANGHAI),
            limit_contract_code_size: Some(100),
            ..Default::default()
        }
    );
}

#[test]
fn spec_id_lookup() {
    let spec = vec![
        (0, SpecIdWrapper::new(SpecId::CONSTANTINOPLE)),
        (10, SpecIdWrapper::new(SpecId::BERLIN)),
        (20, SpecIdWrapper::new(SpecId::LONDON)),
    ];

    assert_eq!(
        get_spec_id(spec.clone(), 0),
        SpecIdWrapper::new(SpecId::CONSTANTINOPLE)
    );
    assert_eq!(
        get_spec_id(spec.clone(), 5),
        SpecIdWrapper::new(SpecId::CONSTANTINOPLE)
    );
    assert_eq!(
        get_spec_id(spec.clone(), 10),
        SpecIdWrapper::new(SpecId::BERLIN)
    );
    assert_eq!(
        get_spec_id(spec.clone(), 15),
        SpecIdWrapper::new(SpecId::BERLIN)
    );
    assert_eq!(
        get_spec_id(spec.clone(), 20),
        SpecIdWrapper::new(SpecId::LONDON)
    );
    assert_eq!(
        get_spec_id(spec.clone(), 25),
        SpecIdWrapper::new(SpecId::LONDON)
    );
}
