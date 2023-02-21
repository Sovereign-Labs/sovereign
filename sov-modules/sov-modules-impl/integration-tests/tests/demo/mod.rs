use borsh::{BorshDeserialize, BorshSerialize};
use example_election::Election;
use example_value_adder::ValueAdderModule;
use sov_modules_api::{
    mocks::{MockContext, MockPublicKey},
    CallResponse, Context, Error, Module, ModuleInfo, QueryResponse,
};
use sov_state::{CacheLog, ValueReader};
use sovereign_sdk::serial::{Decode, Encode};
use std::{io::Cursor, marker::PhantomData};

/// dispatch_tx is a high level interface used by the sdk.
/// Transaction signature must be checked outside of this function.
fn dispatch_tx<C: Context, VR: ValueReader>(
    tx_data: Vec<u8>,
    context: C,
    value_reader: VR,
) -> Result<(CallResponse, CacheLog), Error> {
    // 1. Create Storage (with fresh Cache)
    // 2. Deserialize tx
    // 3. deserialized_tx.dispatch(...)
    todo!()
}

//TODO
fn genesis() {}

/// A trait that needs to be implemented for any call message.
trait DispatchCall {
    type Context: Context;

    /// Dispatches a call message to the appropriate module.
    fn dispatch(
        self,
        storage: <<Self as DispatchCall>::Context as Context>::Storage,
        context: &Self::Context,
    ) -> Result<CallResponse, Error>;
}

/// Runtime defines modules registered in the rollup.
// #[derive(Genesis, DispatchCall, DispatchQuery, Client)]
// TODO rename it to "Spec"?
struct Runtime<C: Context> {
    election: Election<C>,
    value_adder: ValueAdderModule<C>,
    //..
}

// Generated code
#[derive(BorshDeserialize, BorshSerialize)]
enum RuntimeCall<C: Context> {
    Election(<Election<C> as Module>::CallMessage),
    ValueAdder(<ValueAdderModule<C> as Module>::CallMessage),
}

// Generated code
impl<C: Context> DispatchCall for RuntimeCall<C> {
    type Context = C;

    fn dispatch(self, storage: C::Storage, context: &C) -> Result<CallResponse, Error> {
        match self {
            RuntimeCall::Election(message) => {
                let mut election = Election::<C>::new(storage);
                election.call(message, context)
            }
            RuntimeCall::ValueAdder(message) => {
                let mut value_adder = ValueAdderModule::<C>::new(storage);
                value_adder.call(message, context)
            }
        }
    }
}

/// Methods from this trait should be called only once during the rollup deployment.
trait Genesis {
    type Context: Context;

    /// Initializes the state of the rollup.
    // TDOD: genesis should take initial configuration as an argument.
    fn genesis() -> Result<<<Self as Genesis>::Context as Context>::Storage, Error>;
}

// Generated code
impl<C: Context> Genesis for Runtime<C> {
    type Context = C;

    fn genesis() -> Result<C::Storage, Error> {
        let storage = C::Storage::default();

        let mut election = Election::<C>::new(storage.clone());
        election.genesis()?;

        let mut value_adder = ValueAdderModule::<C>::new(storage.clone());
        value_adder.genesis()?;

        Ok(storage)
    }
}

fn decode_dispatchable<C: Context>(
    data: Vec<u8>,
) -> Result<impl DispatchCall<Context = C>, anyhow::Error> {
    let mut data = Cursor::new(data);
    Ok(RuntimeCall::<C>::decode(&mut data)?)
}

// Generated code
// - test client (x)
// - rest api client (TODO)
// - wasm bindings (TODO)
// - json abi (TODO)
#[derive(Default)]
struct Client<C: Context> {
    _phantom: PhantomData<C>,
}

impl<C: Context> Client<C> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn send_election_message(&self, data: <Election<C> as Module>::CallMessage) -> Vec<u8> {
        let call = RuntimeCall::<C>::Election(data);
        let mut data = Vec::default();
        call.encode(&mut data);

        data
    }

    fn send_value_adder_message(
        &self,
        data: <ValueAdderModule<C> as Module>::CallMessage,
    ) -> Vec<u8> {
        let call = RuntimeCall::<C>::ValueAdder(data);
        let mut data = Vec::default();
        call.encode(&mut data);

        data
    }

    fn query_election(&self, data: <Election<C> as Module>::QueryMessage) -> Vec<u8> {
        let query = RuntimeQuery::<C>::Election(data);
        let mut data = Vec::default();
        query.encode(&mut data);

        data
    }

    fn query_value_adder(&self, data: <ValueAdderModule<C> as Module>::QueryMessage) -> Vec<u8> {
        let query = RuntimeQuery::<C>::ValueAdder(data);
        let mut data = Vec::default();
        query.encode(&mut data);

        data
    }
}

// Generated code
#[derive(BorshDeserialize, BorshSerialize)]
enum RuntimeQuery<C: Context> {
    Election(<Election<C> as Module>::QueryMessage),
    ValueAdder(<ValueAdderModule<C> as Module>::QueryMessage),
}

/// A trait that needs to be implemented for any query message.
trait DispatchQuery {
    type Context: Context;

    /// Dispatches a query message to the appropriate module.
    fn dispatch(
        self,
        storage: <<Self as DispatchQuery>::Context as Context>::Storage,
    ) -> QueryResponse;
}

// Generated code
impl<C: Context> DispatchQuery for RuntimeQuery<C> {
    type Context = C;

    fn dispatch(
        self,
        storage: <<Self as DispatchQuery>::Context as Context>::Storage,
    ) -> QueryResponse {
        match self {
            RuntimeQuery::Election(message) => {
                let election = Election::<C>::new(storage);
                election.query(message)
            }
            RuntimeQuery::ValueAdder(message) => {
                let value_adder = ValueAdderModule::<C>::new(storage);
                value_adder.query(message)
            }
        }
    }
}

fn decode_queryable<C: Context>(
    data: Vec<u8>,
) -> Result<impl DispatchQuery<Context = C>, anyhow::Error> {
    let mut data = Cursor::new(data);
    Ok(RuntimeQuery::<C>::decode(&mut data)?)
}

#[test]
fn test_demo() {
    let client = Client::<C>::new();
    type C = MockContext;
    let sender = MockPublicKey::try_from("admin").unwrap();
    let context = MockContext::new(sender);
    let storage = Runtime::<C>::genesis().unwrap();

    // Call the election module.
    {
        let call_message = example_election::call::CallMessage::<C>::SetCandidates {
            names: vec!["candidate_1".to_owned()],
        };

        let serialized_message = client.send_election_message(call_message);
        let module = decode_dispatchable::<C>(serialized_message).unwrap();
        let result = module.dispatch(storage.clone(), &context);
        assert!(result.is_ok())
    }

    // Query the election module.
    {
        let query_message = example_election::query::QueryMessage::Result;

        let serialized_message = client.query_election(query_message);
        let module = decode_queryable::<C>(serialized_message).unwrap();

        let response = module.dispatch(storage);
        let _json_response = std::str::from_utf8(&response.response).unwrap();
    }
}
