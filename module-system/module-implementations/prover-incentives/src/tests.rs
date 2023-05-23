use sov_modules_api::{default_context::DefaultContext, Address, Hasher, Module, ModuleInfo, Spec};
use sov_rollup_interface::mocks::{MockCodeCommitment, MockProof, MockZkvm};
use sov_state::{ProverStorage, WorkingSet};

use crate::ProverIncentives;

type C = DefaultContext;

const BOND_AMOUNT: u64 = 1000;
const MOCK_CODE_COMMITMENT: MockCodeCommitment = MockCodeCommitment([0u8; 32]);

pub fn generate_address(key: &str) -> <C as Spec>::Address {
    let hash = <C as Spec>::Hasher::hash(key.as_bytes());
    Address::from(hash)
}

fn create_bank_config() -> (bank::BankConfig<C>, <C as Spec>::Address) {
    let prover_address = generate_address("prover_pub_key");

    let token_config = bank::TokenConfig {
        token_name: "InitialToken".to_owned(),
        address_and_balances: vec![(prover_address.clone(), BOND_AMOUNT * 5)],
    };

    (
        bank::BankConfig {
            tokens: vec![token_config],
        },
        prover_address,
    )
}

fn setup(
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
) -> (ProverIncentives<C, MockZkvm>, Address) {
    // Initialize bank
    let (bank_config, prover_address) = create_bank_config();
    let bank = bank::Bank::<C>::new();
    bank.genesis(&bank_config, working_set)
        .expect("bank genesis must succeed");

    let token_address = bank::create_token_address::<C>(
        &bank_config.tokens[0].token_name,
        &bank::genesis::DEPLOYER,
        bank::genesis::SALT,
    );

    // initialize prover incentives
    let module = ProverIncentives::<C, MockZkvm>::new();
    let config = crate::ProverIncentivesConfig {
        bonding_token_address: token_address,
        minimum_bond: BOND_AMOUNT,
        commitment_of_allowed_verifier_method: MockCodeCommitment([0u8; 32]),
        initial_provers: vec![(prover_address.clone(), BOND_AMOUNT)],
    };

    module
        .genesis(&config, working_set)
        .expect("prover incentives genesis must succeed");
    (module, prover_address)
}

#[test]
fn test_burn_on_invalid_proof() {
    let storage = ProverStorage::temporary();
    let mut working_set = WorkingSet::new(storage);
    let (module, prover_address) = setup(&mut working_set);

    // Assert that the prover has the correct bond amount before processing the proof
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        BOND_AMOUNT
    );

    // Process an invalid proof
    {
        let context = DefaultContext {
            sender: prover_address.clone(),
        };
        let proof = MockProof {
            program_id: MOCK_CODE_COMMITMENT,
            is_valid: false,
            log: &[],
        };
        module
            .process_proof(proof.encode_to_vec().as_ref(), &context, &mut working_set)
            .expect("An invalid proof is not an error");
    }

    // Assert that the prover's bond amount has been burned
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        0
    );
}

#[test]
fn test_valid_proof() {
    let storage = ProverStorage::temporary();
    let mut working_set = WorkingSet::new(storage);
    let (module, prover_address) = setup(&mut working_set);

    // Assert that the prover has the correct bond amount before processing the proof
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        BOND_AMOUNT
    );

    // Process a valid proof
    {
        let context = DefaultContext {
            sender: prover_address.clone(),
        };
        let proof = MockProof {
            program_id: MOCK_CODE_COMMITMENT,
            is_valid: true,
            log: &[],
        };
        module
            .process_proof(proof.encode_to_vec().as_ref(), &context, &mut working_set)
            .expect("An invalid proof is not an error");
    }

    // Assert that the prover's bond amount has not been burned
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        BOND_AMOUNT
    );
}

#[test]
fn test_unbonding() {
    let storage = ProverStorage::temporary();
    let mut working_set = WorkingSet::new(storage);
    let (module, prover_address) = setup(&mut working_set);
    let context = DefaultContext {
        sender: prover_address.clone(),
    };
    let token_address = module
        .bonding_token_address
        .get(&mut working_set)
        .expect("bonding token address was set at genesis");

    // Assert that the prover has bonded tokens
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        BOND_AMOUNT
    );

    // Get their *unlocked* balance before undbonding
    let initial_unlocked_balance = {
        module
            .bank
            .get_balance_of(
                prover_address.clone(),
                token_address.clone(),
                &mut working_set,
            )
            .unwrap_or_default()
    };

    // Unbond the prover
    module
        .unbond_prover(&context, &mut working_set)
        .expect("Unbonding should succeed");

    // Assert that the prover no longer has bonded tokens
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        0
    );

    // Assert that the prover's unlocked balance has increased by the amount they unbonded
    let unlocked_balance = module.bank.get_balance_of(
        prover_address.clone(),
        token_address.clone(),
        &mut working_set,
    );
    assert_eq!(
        unlocked_balance,
        Some(BOND_AMOUNT + initial_unlocked_balance)
    );
}

#[test]
fn test_prover_not_bonded() {
    let storage = ProverStorage::temporary();
    let mut working_set = WorkingSet::new(storage);
    let (module, prover_address) = setup(&mut working_set);
    let context = DefaultContext {
        sender: prover_address.clone(),
    };

    // Unbond the prover
    module
        .unbond_prover(&context, &mut working_set)
        .expect("Unbonding should succeed");

    // Assert that the prover no longer has bonded tokens
    assert_eq!(
        module
            .get_bond_amount(prover_address.clone(), &mut working_set)
            .value,
        0
    );

    // Process a valid proof
    {
        let proof = MockProof {
            program_id: MOCK_CODE_COMMITMENT,
            is_valid: true,
            log: &[],
        };
        // Assert that processing a valid proof fails
        assert!(module
            .process_proof(proof.encode_to_vec().as_ref(), &context, &mut working_set)
            .is_err())
    }
}
