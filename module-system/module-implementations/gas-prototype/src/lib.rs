use sov_modules_api::CallResponse;
use sov_modules_api::Context;
use sov_modules_api::Error;
use sov_modules_api::Hasher;
use sov_modules_api::ModuleInfo;
use sov_state::{StateValue, WorkingSet};
use std::marker::PhantomData;

pub struct Bank<C: Context> {
    _P: PhantomData<C>,
}

impl<C: Context> Bank<C> {
    fn transfer(&self, working_set: &mut WorkingSet<C::Storage, C::GasUnit>) {}
}

pub struct SomeConfig<C: sov_modules_api::Context> {
    _p: PhantomData<C>,
}

#[cfg_attr(
    feature = "native",
    derive(serde::Serialize),
    derive(serde::Deserialize)
)]
#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq, Clone)]
pub enum CallMessage {
    Method1,
    Method2,
}

pub struct GasConfig<GasUnit> {
    pub matrix_mul_gas: GasUnit,
    pub expensive_check_loop_step_gas: GasUnit,
}

// Generated by  a macro
impl<C: sov_modules_api::Context> ModuleInfo for SomeModule<C> {
    type Context = C;
    type GasConfig = GasConfig<C::GasUnit>;

    fn new(gas_config: Self::GasConfig) -> Self {
        todo!()
    }

    fn address(&self) -> &<Self::Context as sov_modules_api::Spec>::Address {
        todo!()
    }
}

//#[derive(ModuleInfo, Clone)]
pub struct SomeModule<C: sov_modules_api::Context> {
    // #[address]
    pub(crate) address: C::Address,

    // #[gas] Q how do we inject it?
    pub(crate) gas_config: GasConfig<C::GasUnit>,

    /// #[state]
    pub(crate) some_state_value: StateValue<u64>,

    /// #[module]
    pub(crate) bank: Bank<C>,
}

impl<C: sov_modules_api::Context> sov_modules_api::Module for SomeModule<C> {
    type Context = C;

    type Config = SomeConfig<C>;

    type GasConfig = GasConfig<C::GasUnit>;

    type CallMessage = CallMessage;

    fn genesis(
        &self,
        config: &Self::Config,
        working_set: &mut WorkingSet<C::Storage, C::GasUnit>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn call(
        &self,
        msg: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<C::Storage, C::GasUnit>,
    ) -> Result<sov_modules_api::CallResponse, Error> {
        match msg {
            CallMessage::Method1 => Ok(self.some_complex_math_operation(context, working_set)?),
            CallMessage::Method2 => Ok(self.some_expensive_check_in_loop(context, working_set)?),
        }
    }
}

impl<C: sov_modules_api::Context> SomeModule<C> {
    pub(crate) fn some_complex_math_operation(
        &self,
        context: &C,
        working_set: &mut WorkingSet<C::Storage, C::GasUnit>,
    ) -> anyhow::Result<CallResponse> {
        working_set.charge_gas(&self.gas_config.matrix_mul_gas)?;

        //  <Self::Context as sov_modules_api::Spec>::Hasher::hash(&[0; 32], working_set);
        self.some_state_value.set(&22, working_set);

        self.bank.transfer(/*from, to, etc */ working_set);
        todo!()
    }

    pub(crate) fn some_expensive_check_in_loop(
        &self,
        context: &C,
        working_set: &mut WorkingSet<C::Storage, C::GasUnit>,
    ) -> anyhow::Result<CallResponse> {
        for i in 0..100 {
            working_set.charge_gas(&self.gas_config.expensive_check_loop_step_gas)?;
            // some expensive operation

            self.some_state_value.set(&99, working_set);
        }

        todo!()
    }
}
