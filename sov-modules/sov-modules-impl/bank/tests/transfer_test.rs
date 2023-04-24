mod helpers;

use bank::call::CallMessage;
use bank::genesis::{DEPLOYER, SALT};
use bank::query::{BalanceResponse, QueryMessage, TotalSupplyResponse};
use bank::{create_token_address, Bank, Coins};
use helpers::*;
use sov_modules_api::{Address, Context, Module, ModuleInfo};
use sov_state::{ProverStorage, WorkingSet};

#[test]
fn transfer_deployed_token() {}

#[test]
fn transfer_initial_token() {
    let initial_balance = 100;
    let tranfer_amount = 10;
    let bank_config = create_bank_config_with_token(3, initial_balance);
    let mut working_set = WorkingSet::new(ProverStorage::temporary());
    let bank = Bank::new();
    bank.genesis(&bank_config, &mut working_set).unwrap();

    let token_address =
        create_token_address::<C>(&bank_config.tokens[0].token_name, &DEPLOYER, SALT);
    let sender_address = bank_config.tokens[0].address_and_balances[0].0.clone();
    let receiver_address = bank_config.tokens[0].address_and_balances[1].0.clone();
    assert_ne!(sender_address, receiver_address);

    // Preparation
    let query_user_balance =
        |user_address: Address, working_set: &mut WorkingSet<Storage>| -> Option<u64> {
            let query = QueryMessage::GetBalance {
                user_address,
                token_address: token_address.clone(),
            };

            let balance: BalanceResponse = query_and_deserialize(&bank, query, working_set);
            balance.amount
        };

    let query_total_supply = |working_set: &mut WorkingSet<Storage>| -> Option<u64> {
        let query = QueryMessage::GetTotalSupply {
            token_address: token_address.clone(),
        };
        let total_supply: TotalSupplyResponse = query_and_deserialize(&bank, query, working_set);
        total_supply.amount
    };

    let sender_balance_before = query_user_balance(sender_address.clone(), &mut working_set);
    let receiver_balance_before = query_user_balance(receiver_address.clone(), &mut working_set);
    let total_supply_before = query_total_supply(&mut working_set);
    assert!(total_supply_before.is_some());

    assert_eq!(Some(initial_balance), sender_balance_before);
    assert_eq!(sender_balance_before, receiver_balance_before);
    let sender_context = C::new(sender_address.clone());

    // Transfer happy test
    {
        let transfer_message = CallMessage::Transfer {
            to: receiver_address.clone(),
            coins: Coins {
                amount: tranfer_amount,
                token_address: token_address.clone(),
            },
        };

        let transferred = bank
            .call(transfer_message, &sender_context, &mut working_set)
            .expect("Transfer call failed");

        assert!(transferred.events.is_empty());

        let sender_balance_after = query_user_balance(sender_address.clone(), &mut working_set);
        let receiver_balance_after = query_user_balance(receiver_address.clone(), &mut working_set);

        assert_eq!(Some(initial_balance - tranfer_amount), sender_balance_after);
        assert_eq!(
            Some(initial_balance + tranfer_amount),
            receiver_balance_after
        );
        let total_supply_after = query_total_supply(&mut working_set);
        assert_eq!(total_supply_before, total_supply_after);
    }

    // Not enough balance
    {
        let transfer_message = CallMessage::Transfer {
            to: receiver_address.clone(),
            coins: Coins {
                amount: initial_balance + 1,
                token_address: token_address.clone(),
            },
        };

        let result = bank.call(transfer_message, &sender_context, &mut working_set);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert_eq!("Insufficient funds", error.to_string());
    }

    // Non existent token
    {
        let salt = 0;
        let token_name = "NonExistingToken".to_owned();
        let token_address = create_token_address::<C>(&token_name, sender_address.as_ref(), salt);

        let transfer_message = CallMessage::Transfer {
            to: receiver_address.clone(),
            coins: Coins {
                amount: 1,
                token_address: token_address.clone(),
            },
        };

        let result = bank.call(transfer_message, &sender_context, &mut working_set);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error
            .to_string()
            .contains("Value not found for prefix: \"bank/Bank/tokens/\" and: storage key"))
    }

    // Sender does not exist
    {
        let unknown_sender = generate_address("non_existing_sender");
        let unknown_sender_context = C::new(unknown_sender.clone());

        let sender_balance = query_user_balance(unknown_sender.clone(), &mut working_set);
        assert!(sender_balance.is_none());

        let receiver_balance_before =
            query_user_balance(receiver_address.clone(), &mut working_set);

        let transfer_message = CallMessage::Transfer {
            to: receiver_address.clone(),
            coins: Coins {
                amount: 1,
                token_address: token_address.clone(),
            },
        };

        let result = bank.call(transfer_message, &unknown_sender_context, &mut working_set);
        assert!(result.is_err());

        let error = result.err().unwrap();
        // TODO: Prefix just address https://github.com/Sovereign-Labs/sovereign/issues/185
        assert!(error
            .to_string()
            .contains("Value not found for prefix: 0xc166b1b9c394ac408de38dd16fdba54edfcb3f7502f42ed59f296b93216f34f4 and: storage key"));

        let receiver_balance_after = query_user_balance(receiver_address.clone(), &mut working_set);
        assert_eq!(receiver_balance_before, receiver_balance_after);
    }

    // Receiver does not exist
    
    // Sender equals receiver
}
