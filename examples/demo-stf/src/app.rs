#[cfg(feature = "native")]
pub use sov_modules_api::default_context::DefaultContext;
pub use sov_modules_api::default_context::ZkDefaultContext;
#[cfg(feature = "native")]
pub use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
#[cfg(feature = "native")]
use sov_modules_api::Spec;
use sov_modules_stf_template::AppTemplate;
pub use sov_modules_stf_template::Batch;
use sov_rollup_interface::da::{BlobReaderTrait, DaSpec};
use sov_rollup_interface::zk::{ValidityCondition, Zkvm};
#[cfg(feature = "native")]
use sov_state::ProverStorage;
use sov_state::{Storage, ZkStorage};
#[cfg(feature = "native")]
use sov_stf_runner::FiFoStrictBatchBuilder;
#[cfg(feature = "native")]
use sov_stf_runner::StorageConfig;

use crate::runtime::Runtime;

//TODO CHANGE B TO DaSpec
#[cfg(feature = "native")]
pub struct App<Vm: Zkvm, DA: DaSpec> {
    pub stf: AppTemplate<
        DefaultContext,
        DA::ValidityCondition,
        Vm,
        Runtime<DefaultContext>,
        DA::BlobTransaction,
    >,
    pub batch_builder: Option<FiFoStrictBatchBuilder<Runtime<DefaultContext>, DefaultContext>>,
}

#[cfg(feature = "native")]
impl<Vm: Zkvm, DA: DaSpec> App<Vm, DA> {
    pub fn new(storage_config: StorageConfig) -> Self {
        let storage =
            ProverStorage::with_config(storage_config).expect("Failed to open prover storage");
        let app = AppTemplate::new(storage.clone(), Runtime::default());
        let batch_size_bytes = 1024 * 100; // 100 KB
        let batch_builder = FiFoStrictBatchBuilder::new(
            batch_size_bytes,
            u32::MAX as usize,
            Runtime::default(),
            storage,
        );
        Self {
            stf: app,
            batch_builder: Some(batch_builder),
        }
    }

    pub fn get_storage(&self) -> <DefaultContext as Spec>::Storage {
        self.stf.current_storage.clone()
    }
}

pub fn create_zk_app_template<Vm: Zkvm, Cond: ValidityCondition, B: BlobReaderTrait>(
    runtime_config: [u8; 32],
) -> AppTemplate<ZkDefaultContext, Cond, Vm, Runtime<ZkDefaultContext>, B> {
    let storage = ZkStorage::with_config(runtime_config).expect("Failed to open zk storage");
    AppTemplate::new(storage, Runtime::default())
}
