mod batch;
mod data_generation;
mod helpers;
mod runtime;

mod stf;
mod tx_hooks;
mod tx_verifier;

use std::path::Path;

use data_generation::{simulate_da, QueryGenerator};
use helpers::check_query;
use runtime::Runtime;
use sov_modules_api::mocks::MockContext;
use sov_state::ProverStorage;
use sovereign_sdk::stf::StateTransitionFunction;
use stf::Demo;
use tx_hooks::DemoAppTxHooks;
use tx_verifier::DemoAppTxVerifier;

type C = MockContext;
type DemoApp = Demo<C, DemoAppTxVerifier<C>, Runtime<C>, DemoAppTxHooks<C>>;

fn create_new_demo(path: impl AsRef<Path>) -> DemoApp {
    let runtime = Runtime::new();
    let storage = ProverStorage::with_path(path).unwrap();
    let tx_hooks = DemoAppTxHooks::new();
    let tx_verifier = DemoAppTxVerifier::new();

    Demo::new(storage, runtime, tx_verifier, tx_hooks)
}

fn main() {
    let path = schemadb::temppath::TempPath::new();
    {
        let mut demo = create_new_demo(&path);
        demo.init_chain(());
        demo.begin_slot();

        let txs = simulate_da();

        demo.apply_batch(batch::Batch { txs }, &[1u8; 32], None)
            .expect("Batch is valid");

        demo.end_slot();
    }

    // Checks
    {
        let runtime = &mut Runtime::<MockContext>::new();
        let storage = ProverStorage::with_path(&path).unwrap();
        check_query(
            runtime,
            QueryGenerator::generate_query_election_message(),
            r#"{"Result":{"name":"candidate_2","count":3}}"#,
            storage.clone(),
        );

        check_query(
            runtime,
            QueryGenerator::generate_query_value_setter_message(),
            r#"{"value":33}"#,
            storage,
        );
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_demo_values_in_db() {
        let path = schemadb::temppath::TempPath::new();
        {
            let mut demo = create_new_demo(&path);

            demo.init_chain(());
            demo.begin_slot();

            let txs = simulate_da();

            demo.apply_batch(batch::Batch { txs }, &[1u8; 32], None)
                .expect("Batch is valid");

            demo.end_slot();
        }

        // Generate a new storage instance after dumping data to the db.
        {
            let runtime = &mut Runtime::<MockContext>::new();
            let storage = ProverStorage::with_path(&path).unwrap();
            check_query(
                runtime,
                QueryGenerator::generate_query_election_message(),
                r#"{"Result":{"name":"candidate_2","count":3}}"#,
                storage.clone(),
            );

            check_query(
                runtime,
                QueryGenerator::generate_query_value_setter_message(),
                r#"{"value":33}"#,
                storage,
            );
        }
    }

    #[test]
    fn test_demo_values_in_cache() {
        let path = schemadb::temppath::TempPath::new();
        let mut demo = create_new_demo(&path);

        demo.init_chain(());
        demo.begin_slot();

        let txs = simulate_da();

        demo.apply_batch(batch::Batch { txs }, &[1u8; 32], None)
            .expect("Batch is valid");
        demo.end_slot();

        let runtime = &mut Runtime::<MockContext>::new();
        check_query(
            runtime,
            QueryGenerator::generate_query_election_message(),
            r#"{"Result":{"name":"candidate_2","count":3}}"#,
            demo.current_storage.clone(),
        );

        check_query(
            runtime,
            QueryGenerator::generate_query_value_setter_message(),
            r#"{"value":33}"#,
            demo.current_storage,
        );
    }

    #[test]
    fn test_demo_values_not_in_db() {
        let path = schemadb::temppath::TempPath::new();
        {
            let mut demo = create_new_demo(&path);

            demo.init_chain(());
            demo.begin_slot();

            let txs = simulate_da();

            demo.apply_batch(batch::Batch { txs }, &[1u8; 32], None)
                .expect("Batch is valid");
        }

        // Generate a new storage instance, value are missing because we didn't call `end_slot()`;
        {
            let runtime = &mut Runtime::<C>::new();
            let storage = ProverStorage::with_path(&path).unwrap();
            check_query(
                runtime,
                QueryGenerator::generate_query_election_message(),
                r#"{"Err":"Election is not frozen"}"#,
                storage.clone(),
            );

            check_query(
                runtime,
                QueryGenerator::generate_query_value_setter_message(),
                r#"{"value":null}"#,
                storage,
            );
        }
    }
}
