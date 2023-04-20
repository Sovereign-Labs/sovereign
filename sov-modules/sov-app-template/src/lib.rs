mod batch;
mod tx_hooks;
mod tx_verifier;

pub use batch::Batch;
pub use tx_hooks::TxHooks;
pub use tx_hooks::VerifiedTx;
pub use tx_verifier::{RawTx, TxVerifier};

use sov_modules_api::{Context, DispatchCall, Genesis};
use sov_state::{Storage, WorkingSet};
use sovereign_sdk::{
    core::{mocks::MockProof, traits::BatchTrait},
    jmt,
    stf::{OpaqueAddress, StateTransitionFunction},
};

pub struct AppTemplate<C: Context, V, RT, H, GenesisConfig> {
    pub current_storage: C::Storage,
    pub runtime: RT,
    tx_verifier: V,
    tx_hooks: H,
    genesis_config: GenesisConfig,
    working_set: Option<WorkingSet<C::Storage>>,
}

impl<C: Context, V, RT, H, GenesisConfig> AppTemplate<C, V, RT, H, GenesisConfig>
where
    RT: DispatchCall<Context = C> + Genesis<Context = C, Config = GenesisConfig>,
    V: TxVerifier,
    H: TxHooks<Context = C, Transaction = <V as TxVerifier>::Transaction>,
{
    pub fn new(
        storage: C::Storage,
        runtime: RT,
        tx_verifier: V,
        tx_hooks: H,
        genesis_config: GenesisConfig,
    ) -> Self {
        Self {
            runtime,
            current_storage: storage,
            tx_verifier,
            tx_hooks,
            genesis_config,
            working_set: None,
        }
    }

    fn revert_and_slash(&mut self, batch_workspace: WorkingSet<C::Storage>) {
        // Revert all the changes (the sequencer funds are no longer locked)
        let mut batch_workspace = batch_workspace.revert();

        // Locks funds again, we know there are enough coins to lock.
        self.tx_hooks
            .post_revert_apply_batch(&mut batch_workspace)
            .unwrap();

        // Only the locked_coins are saved in the `AppTemplate`.
        self.working_set = Some(batch_workspace);
    }
}

impl<C: Context, V, RT, H, GenesisConfig> StateTransitionFunction
    for AppTemplate<C, V, RT, H, GenesisConfig>
where
    RT: DispatchCall<Context = C> + Genesis<Context = C, Config = GenesisConfig>,
    V: TxVerifier,
    H: TxHooks<Context = C, Transaction = <V as TxVerifier>::Transaction>,
{
    type StateRoot = jmt::RootHash;

    type ChainParams = ();

    type Transaction = RawTx;

    type Batch = Batch;

    type Proof = MockProof;

    type MisbehaviorProof = ();

    fn init_chain(&mut self, _params: Self::ChainParams) {
        let working_set = &mut WorkingSet::new(self.current_storage.clone());

        self.runtime
            .genesis(&self.genesis_config, working_set)
            .expect("module initialization must succeed");

        let (log, witness) = working_set.freeze();
        self.current_storage
            .validate_and_commit(log, &witness)
            .expect("Storage update must succeed");
    }

    fn begin_slot(&mut self) {
        self.working_set = Some(WorkingSet::new(self.current_storage.clone()));
    }

    fn apply_batch(
        &mut self,
        batch: Self::Batch,
        sequencer: &[u8],
        _misbehavior_hint: Option<Self::MisbehaviorProof>,
    ) -> anyhow::Result<Vec<Vec<sovereign_sdk::stf::Event>>> {
        let mut batch_workspace = WorkingSet::new(self.current_storage.clone());
        batch_workspace = batch_workspace.to_revertable();

        if let Err(e) = self
            .tx_hooks
            .enter_apply_batch(sequencer, &mut batch_workspace)
        {
            anyhow::bail!(
                "Error: The transaction was rejected by the 'enter_apply_batch' hook. {}",
                e
            )
        }

        let mut events = Vec::new();

        // Run the stateless verification.
        let txs = match self
            .tx_verifier
            .verify_txs_stateless(batch.take_transactions())
        {
            Ok(txs) => txs,
            Err(e) => {
                self.revert_and_slash(batch_workspace);
                anyhow::bail!("Stateless verification error - the sequencer included a transaction which was known to be invalid. {}", e);
            }
        };

        for tx in txs {
            batch_workspace = batch_workspace.to_revertable();
            // Run the stateful verification, possibly modifies the state.
            let verified_tx = match self.tx_hooks.pre_dispatch_tx_hook(tx, &mut batch_workspace) {
                Ok(verified_tx) => verified_tx,
                Err(e) => {
                    // TODO check if we want to slash here.
                    let batch_workspace = batch_workspace.revert();
                    self.working_set = Some(batch_workspace);

                    anyhow::bail!("Stateful verification error - the sequencer included an invalid transaction: {}", e);
                }
            };

            match RT::decode_call(verified_tx.runtime_message()) {
                Ok(msg) => {
                    let ctx = C::new(verified_tx.sender().clone());
                    let tx_result = self.runtime.dispatch_call(msg, &mut batch_workspace, &ctx);

                    self.tx_hooks
                        .post_dispatch_tx_hook(verified_tx, &mut batch_workspace);

                    match tx_result {
                        Ok(resp) => {
                            events.push(resp.events);
                            batch_workspace = batch_workspace.commit();
                        }
                        Err(e) => {
                            self.revert_and_slash(batch_workspace);
                            panic!("Demo app txs must succeed but failed with err: {}", e)
                        }
                    }
                }
                Err(e) => {
                    // If the serialization is invalid, the sequencer is malicious. Slash them.
                    self.revert_and_slash(batch_workspace);
                    anyhow::bail!("Tx decoding error: {}", e);
                }
            }
        }

        // TODO: calculate the amount based of gas and fees
        self.tx_hooks
            .exit_apply_batch(0, &mut batch_workspace)
            .expect("Impossible happened: error in exit_apply_batch");

        self.working_set = Some(batch_workspace);

        Ok(events)
    }

    fn apply_proof(
        &self,
        _proof: Self::Proof,
        _prover: &[u8],
    ) -> Result<(), sovereign_sdk::stf::ConsensusSetUpdate<OpaqueAddress>> {
        todo!()
    }

    fn end_slot(
        &mut self,
    ) -> (
        Self::StateRoot,
        Vec<sovereign_sdk::stf::ConsensusSetUpdate<OpaqueAddress>>,
    ) {
        let (cache_log, witness) = self.working_set.take().unwrap().freeze();
        let root_hash = self
            .current_storage
            .validate_and_commit(cache_log, &witness)
            .expect("jellyfish merkle tree update must succeed");
        (jmt::RootHash(root_hash), vec![])
    }
}
