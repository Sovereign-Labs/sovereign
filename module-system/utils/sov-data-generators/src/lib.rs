use std::rc::Rc;

use borsh::ser::BorshSerialize;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Address, Context, DispatchCall, Hasher, MessageCodec, Spec};
use sov_modules_stf_template::RawTx;

pub mod bank_data;
pub mod election_data;
pub mod value_setter_data;

type C = DefaultContext;

pub fn generate_address(key: &str) -> <C as Spec>::Address {
    let hash = <C as Spec>::Hasher::hash(key.as_bytes());
    Address::from(hash)
}

pub trait MessageGenerator {
    type Call;

    fn create_messages(&self) -> Vec<(Rc<DefaultPrivateKey>, Self::Call, u64)>;

    fn create_tx(
        &self,
        sender: &DefaultPrivateKey,
        message: Self::Call,
        nonce: u64,
        is_last: bool,
    ) -> Transaction<DefaultContext>;

    fn create_raw_txs(&self) -> Vec<RawTx> {
        let mut messages_iter = self.create_messages().into_iter().peekable();
        let mut serialized_messages = Vec::default();
        while let Some((sender, m, nonce)) = messages_iter.next() {
            let is_last = messages_iter.peek().is_none();

            let tx = self.create_tx(&sender, m, nonce, is_last);

            serialized_messages.push(RawTx {
                data: tx.try_to_vec().unwrap(),
            })
        }
        serialized_messages
    }
}

#[derive(DispatchCall, MessageCodec)]
#[serialization(borsh::BorshDeserialize, borsh::BorshSerialize)]
pub struct Runtime<C: Context> {
    pub bank: sov_bank::Bank<C>,
    pub election: sov_election::Election<C>,
    pub value_setter: sov_value_setter::ValueSetter<C>,
}
