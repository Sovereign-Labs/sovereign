mod call;
mod genesis;
mod query;
use sov_modules_api::Error;
use sov_modules_macros::ModuleInfo;
use sov_state::WorkingSet;

type Amount = u64;

#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq)]
pub struct Coins<Address: sov_modules_api::AddressTrait> {
    amount: Amount,
    token_address: Address,
}

#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq, Clone)]
pub struct Token<Address: sov_modules_api::AddressTrait> {
    name: String,
    total_supply: u64,
    balances: sov_state::StateMap<Address, Amount>,
}

#[derive(ModuleInfo)]
pub struct Bank<C: sov_modules_api::Context> {
    #[address]
    pub address: C::Address,

    #[state]
    pub names: sov_state::StateMap<String, C::Address>,

    #[state]
    pub tokens: sov_state::StateMap<C::Address, Token<C::Address>>,
}

impl<C: sov_modules_api::Context> sov_modules_api::Module for Bank<C> {
    type Context = C;

    type CallMessage = call::CallMessage<C>;

    type QueryMessage = query::QueryMessage<C>;

    fn genesis(&self, working_set: &mut WorkingSet<C::Storage>) -> Result<(), Error> {
        Ok(self.init_module(working_set)?)
    }

    fn call(
        &self,
        _msg: Self::CallMessage,
        _context: &Self::Context,
        _working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, Error> {
        todo!()
    }

    #[cfg(feature = "native")]
    fn query(
        &self,
        _msg: Self::QueryMessage,
        _working_set: &mut WorkingSet<C::Storage>,
    ) -> sov_modules_api::QueryResponse {
        todo!()
    }
}
