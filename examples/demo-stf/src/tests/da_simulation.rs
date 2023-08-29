use std::rc::Rc;

use sov_data_generators::bank_data::{
    BadNonceBankCallMessages, BadSerializationBankCallMessages, BadSignatureBankCallMessages,
    BankMessageGenerator,
};
use sov_data_generators::value_setter_data::{ValueSetterMessage, ValueSetterMessages};
use sov_data_generators::MessageGenerator;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_stf_template::RawTx;

use crate::runtime::Runtime;

type C = DefaultContext;

pub fn simulate_da(value_setter_admin: DefaultPrivateKey) -> Vec<RawTx> {
    let mut messages = Vec::default();

    let bank_generator = BankMessageGenerator::<C>::default();
    let bank_txns = bank_generator.create_raw_txs::<Runtime<C>>();

    let value_setter = ValueSetterMessages::new(vec![ValueSetterMessage {
        admin: Rc::new(value_setter_admin),
        messages: vec![99, 33],
    }]);
    messages.extend(value_setter.create_raw_txs::<Runtime<C>>());
    messages.extend(bank_txns);
    messages
}

pub fn simulate_da_with_revert_msg() -> Vec<RawTx> {
    let mut messages = Vec::default();
    let bank_generator = BankMessageGenerator::<C>::create_invalid_transfer();
    let bank_txns = bank_generator.create_raw_txs::<Runtime<C>>();
    messages.extend(bank_txns);
    messages
}

pub fn simulate_da_with_bad_sig() -> Vec<RawTx> {
    let b: BadSignatureBankCallMessages = Default::default();
    b.create_raw_txs::<Runtime<C>>()
}

pub fn simulate_da_with_bad_nonce() -> Vec<RawTx> {
    let b: BadNonceBankCallMessages = Default::default();
    b.create_raw_txs::<Runtime<C>>()
}

pub fn simulate_da_with_bad_serialization() -> Vec<RawTx> {
    let b: BadSerializationBankCallMessages = Default::default();
    b.create_raw_txs::<Runtime<C>>()
}
