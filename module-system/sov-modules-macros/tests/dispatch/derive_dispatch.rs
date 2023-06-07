mod modules;
use modules::{first_test_module, second_test_module};
use sov_modules_api::Address;
use sov_modules_api::ModuleInfo;
use sov_modules_api::{default_context::DefaultContext, Context, Genesis, Module};
use sov_modules_macros::{DefaultRuntime, DispatchCall, Genesis, MessageCodec};
use sov_state::ProverStorage;

#[derive(Genesis, DispatchCall, MessageCodec, DefaultRuntime)]
#[serialization(borsh::BorshDeserialize, borsh::BorshSerialize)]
struct Runtime<C: Context> {
    pub first: first_test_module::FirstTestStruct<C>,
    pub second: second_test_module::SecondTestStruct<C>,
}

fn main() {
    use sov_modules_api::DispatchCall;
    type RT = Runtime<DefaultContext>;
    let runtime = &mut RT::default();

    let tmpdir = tempfile::tempdir().unwrap();
    let storage = ProverStorage::with_path(tmpdir.path()).unwrap();
    let mut working_set = &mut sov_state::WorkingSet::new(storage);
    let config = GenesisConfig::new((), ());
    runtime.genesis(&config, working_set).unwrap();
    let context = DefaultContext::new(Address::try_from([0; 32].as_ref()).unwrap());

    let value = 11;
    {
        let message = value;
        let serialized_message = RT::encode_first_call(message);
        let module = RT::decode_call(&serialized_message).unwrap();

        assert_eq!(runtime.module_address(&module), runtime.first.address());
        let _ = runtime
            .dispatch_call(module, working_set, &context)
            .unwrap();
    }

    {
        let response = runtime.first.get_state_value(&mut working_set);
        assert_eq!(response, value);
    }

    let value = 22;
    {
        let message = value;
        let serialized_message = RT::encode_second_call(message);
        let module = RT::decode_call(&serialized_message).unwrap();

        assert_eq!(runtime.module_address(&module), runtime.second.address());

        let _ = runtime
            .dispatch_call(module, working_set, &context)
            .unwrap();
    }

    {
        let response = runtime.second.get_state_value(&mut working_set);
        assert_eq!(response, value);
    }
}
