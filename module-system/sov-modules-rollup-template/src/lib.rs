#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod runtime_rpc;
mod wallet;
use std::net::SocketAddr;

use async_trait::async_trait;
pub use runtime_rpc::*;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::{Context, DaSpec, Spec};
use sov_modules_stf_template::{AppTemplate, Runtime as RuntimeTrait};
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_state::storage::NativeStorage;
use sov_stf_runner::verifier::StateTransitionVerifier;
use sov_stf_runner::{ProofGenConfig, Prover, RollupConfig, StateTransitionRunner};
use tokio::sync::oneshot;
pub use wallet::*;

/// This trait defines how to crate all the necessary dependencies required by a rollup.
#[async_trait]
pub trait RollupTemplate: Sized + Send + Sync {
    /// Data Availability service.
    type DaService: DaService<Spec = Self::DaSpec, Error = anyhow::Error> + Clone + Send + Sync;
    /// A specification for the types used by a DA layer.
    type DaSpec: DaSpec + Send + Sync;
    /// Data Availability config.
    type DaConfig: Send + Sync;

    /// Host of a zkVM program.
    type Vm: ZkvmHost + Send;

    /// Context for Zero Knowledge environment.
    type ZkContext: Context;
    /// Context for Native environment.
    type NativeContext: Context;

    /// Runtime for Zero Knowledge environment.
    type ZkRuntime: RuntimeTrait<Self::ZkContext, Self::DaSpec> + Default;
    /// Runtime for Native environment.
    type NativeRuntime: RuntimeTrait<Self::NativeContext, Self::DaSpec> + Default + Send + Sync;

    /// Creates RPC methods for the rollup.
    fn create_rpc_methods(
        &self,
        storage: &<Self::NativeContext as Spec>::Storage,
        ledger_db: &LedgerDB,
        da_service: &Self::DaService,
    ) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error>;

    /// Creates GenesisConfig from genesis files.
    fn create_genesis_config(
        &self,
        genesis_paths: &<Self::NativeRuntime as RuntimeTrait<Self::NativeContext, Self::DaSpec>>::GenesisPaths,
        _rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> anyhow::Result<
        <Self::NativeRuntime as RuntimeTrait<Self::NativeContext, Self::DaSpec>>::GenesisConfig,
    > {
        <Self::NativeRuntime as RuntimeTrait<Self::NativeContext, Self::DaSpec>>::genesis_config(
            genesis_paths,
        )
    }

    /// Creates instance of DA Service.
    async fn create_da_service(
        &self,
        rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> Self::DaService;

    /// Creates instance of ZK storage.
    fn create_zk_storage(
        &self,
        rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> <Self::ZkContext as Spec>::Storage;

    /// Creates instance of Native storage.
    fn create_native_storage(
        &self,
        rollup_config: &RollupConfig<Self::DaConfig>,
    ) -> Result<<Self::NativeContext as Spec>::Storage, anyhow::Error>;

    /// Creates instance of ZkVm.
    fn create_vm(&self) -> Self::Vm;

    /// Creates instance of DA Verifier.
    fn create_verifier(&self) -> <Self::DaService as DaService>::Verifier;

    /// Creates instance of a LedgerDB.
    fn create_ledger_db(&self, rollup_config: &RollupConfig<Self::DaConfig>) -> LedgerDB {
        LedgerDB::with_path(&rollup_config.storage.path).expect("Ledger DB failed to open")
    }

    /// Creates a new rollup.
    async fn create_new_rollup(
        &self,
        genesis_paths: &<Self::NativeRuntime as RuntimeTrait<Self::NativeContext, Self::DaSpec>>::GenesisPaths,
        rollup_config: RollupConfig<Self::DaConfig>,
        prover_config: Option<RollupProverConfig>,
    ) -> Result<Rollup<Self>, anyhow::Error>
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let da_service = self.create_da_service(&rollup_config).await;
        let ledger_db = self.create_ledger_db(&rollup_config);
        let genesis_config = self.create_genesis_config(genesis_paths, &rollup_config)?;

        let prover = prover_config.map(|pc| {
            configure_prover(
                self.create_vm(),
                pc,
                self.create_verifier(),
                self.create_zk_storage(&rollup_config),
            )
        });

        let storage = self.create_native_storage(&rollup_config)?;

        let prev_root = ledger_db
            .get_head_slot()?
            .map(|(number, _)| storage.get_root_hash(number.0))
            .transpose()?;

        let rpc_methods = self.create_rpc_methods(&storage, &ledger_db, &da_service)?;

        let native_stf = AppTemplate::new(storage);

        let runner = StateTransitionRunner::new(
            rollup_config.runner,
            da_service,
            ledger_db,
            native_stf,
            prev_root,
            genesis_config,
            prover,
        )?;

        Ok(Rollup {
            runner,
            rpc_methods,
        })
    }
}

/// The possible configurations of the prover.
pub enum RollupProverConfig {
    /// Run the rollup verification logic inside the current process
    Simulate,
    /// Run the rollup verifier in a zkVM executor
    Execute,
    /// Run the rollup verifier and create a SNARK of execution
    Prove,
}

/// Dependencies needed to run the rollup.
pub struct Rollup<S: RollupTemplate> {
    /// The State Transition Runner.
    #[allow(clippy::type_complexity)]
    pub runner: StateTransitionRunner<
        AppTemplate<S::NativeContext, S::DaSpec, S::Vm, S::NativeRuntime>,
        S::DaService,
        S::Vm,
        AppTemplate<S::ZkContext, S::DaSpec, <S::Vm as ZkvmHost>::Guest, S::ZkRuntime>,
    >,
    /// Rpc methods for the rollup.
    pub rpc_methods: jsonrpsee::RpcModule<()>,
}

impl<S: RollupTemplate> Rollup<S> {
    /// Runs the rollup.
    pub async fn run(self) -> Result<(), anyhow::Error> {
        self.run_and_report_rpc_port(None).await
    }

    /// Runs the rollup. Reports rpc port to the caller using the provided channel.
    pub async fn run_and_report_rpc_port(
        self,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        let mut runner = self.runner;
        runner.start_rpc_server(self.rpc_methods, channel).await;
        runner.run_in_process().await?;
        Ok(())
    }
}

type AppVerifier<DA, Zk, ZkContext, RT> =
    StateTransitionVerifier<AppTemplate<ZkContext, <DA as DaVerifier>::Spec, Zk, RT>, DA, Zk>;

type ZkProver<ZkContext, Vm, ZkRuntime, Da> = Prover<
    AppTemplate<ZkContext, <Da as DaService>::Spec, <Vm as ZkvmHost>::Guest, ZkRuntime>,
    Da,
    Vm,
>;

fn configure_prover<
    ZkContext: Context,
    Vm: ZkvmHost,
    Da: DaService,
    RT: RuntimeTrait<ZkContext, <Da as DaService>::Spec> + Default,
>(
    vm: Vm,
    cfg: RollupProverConfig,
    da_verifier: Da::Verifier,
    zk_storage: <ZkContext as Spec>::Storage,
) -> ZkProver<ZkContext, Vm, RT, Da> {
    let app = AppTemplate::new(zk_storage);
    let app_verifier = AppVerifier::<_, _, ZkContext, RT>::new(app, da_verifier);

    let config = match cfg {
        RollupProverConfig::Simulate => ProofGenConfig::Simulate(app_verifier),
        RollupProverConfig::Execute => ProofGenConfig::Execute,
        RollupProverConfig::Prove => ProofGenConfig::Prover,
    };
    ZkProver { vm, config }
}
