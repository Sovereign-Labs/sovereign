use super::ExampleModule;
use crate::{call, query, ExampleModuleConfig};

use sov_modules_api::default_context::{DefaultContext, ZkDefaultContext};
use sov_modules_api::{Address, Context};
use sov_modules_api::{Module, ModuleInfo};
use sov_state::{ProverStorage, WorkingSet, ZkStorage};
use sovereign_core::stf::Event;

#[test]
fn test_value_setter() {
    let mut working_set = WorkingSet::new(ProverStorage::temporary());
    let admin = Address::from([1; 32]);
    // Test Native-Context
    {
        let config = ExampleModuleConfig {};
        let context = DefaultContext::new(admin.clone());
        test_value_setter_helper(context, &config, &mut working_set);
    }

    let (_, witness) = working_set.freeze();

    // Test Zk-Context
    {
        let config = ExampleModuleConfig {};
        let zk_context = ZkDefaultContext::new(admin);
        let mut zk_working_set = WorkingSet::with_witness(ZkStorage::new([0u8; 32]), witness);
        test_value_setter_helper(zk_context, &config, &mut zk_working_set);
    }
}

fn test_value_setter_helper<C: Context>(
    context: C,
    config: &ExampleModuleConfig,
    working_set: &mut WorkingSet<C::Storage>,
) {
    let module = ExampleModule::<C>::new();
    module.genesis(config, working_set).unwrap();

    let new_value = 99;
    let call_msg = call::CallMessage::SetValue(new_value);

    // Test events
    {
        let call_response = module.call(call_msg, &context, working_set).unwrap();
        let event = &call_response.events[0];
        assert_eq!(event, &Event::new("set", "value_set: 99"));
    }

    let query_msg = query::QueryMessage::GetValue;
    let query = module.query(query_msg, working_set);

    // Test query
    {
        let query_response: Result<query::Response, _> = serde_json::from_slice(&query.response);

        assert_eq!(
            query::Response {
                value: Some(new_value)
            },
            query_response.unwrap()
        )
    }
}
