mod modules;

use modules::{first_test_module, second_test_module};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Context, Module, ModuleInfo};
use sov_modules_macros::{DispatchCall, Genesis, MessageCodec};
use sov_state::ProverStorage;

// Debugging hint: To expand the macro in tests run: `cargo expand --test tests`
#[derive(Genesis, DispatchCall, MessageCodec)]
#[serialization(borsh::BorshDeserialize, borsh::BorshSerialize)]
struct Runtime<C>
where
    C: Context,
{
    pub first: first_test_module::FirstTestStruct<C>,
    pub second: second_test_module::SecondTestStruct<C>,
}

impl<C: Context> Runtime<C> {
    fn new() -> Self {
        Self {
            first: first_test_module::FirstTestStruct::<C>::new(),
            second: second_test_module::SecondTestStruct::<C>::new(),
        }
    }
}

fn main() {
    use sov_modules_api::Genesis;

    type C = DefaultContext;
    let storage = ProverStorage::temporary();
    let mut working_set = &mut sov_state::WorkingSet::new(storage);
    let runtime = &mut Runtime::<C>::new();
    let config = GenesisConfig::new((), ());
    runtime.genesis(&config, working_set).unwrap();

    {
        let response = runtime.first.get_state_value(&mut working_set);
        assert_eq!(response, 1);
    }

    {
        let response = runtime.second.get_state_value(&mut working_set);
        assert_eq!(response, 2);
    }
}
