pub mod call;
mod genesis;

#[cfg(test)]
mod tests;

#[cfg(feature = "native")]
pub mod query;

#[cfg(feature = "native")]
use self::query::QueryMessage;

use self::call::CallMessage;
use sov_modules_api::{Address, Error};
use sov_modules_macros::ModuleInfo;
use sov_state::WorkingSet;

#[derive(ModuleInfo)]
pub struct ValueSetter<C: sov_modules_api::Context> {
    #[state]
    pub value: sov_state::StateValue<u32, C::Storage>,

    #[state]
    pub admin: sov_state::StateValue<Address, C::Storage>,
}

impl<C: sov_modules_api::Context> sov_modules_api::Module for ValueSetter<C> {
    type Context = C;

    type CallMessage = CallMessage;

    #[cfg(feature = "native")]
    type QueryMessage = QueryMessage;

    fn genesis(&self, working_set: &mut WorkingSet<C::Storage>) -> Result<(), Error> {
        Ok(self.init_module(working_set)?)
    }

    fn call(
        &self,
        msg: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, Error> {
        match msg {
            CallMessage::DoSetValue(set_value) => {
                Ok(self.set_value(set_value.new_value, context, working_set)?)
            }
        }
    }

    #[cfg(feature = "native")]
    fn query(
        &self,
        msg: Self::QueryMessage,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> sov_modules_api::QueryResponse {
        match msg {
            QueryMessage::GetValue => {
                let response = serde_json::to_vec(&self.query_value(working_set)).unwrap();
                sov_modules_api::QueryResponse { response }
            }
        }
    }
}
