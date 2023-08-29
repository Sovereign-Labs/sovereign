use std::sync::Mutex;

use risc0_zkvm::receipt::Receipt;
use risc0_zkvm::serde::to_vec;
use risc0_zkvm::{
    Executor, ExecutorEnvBuilder, LocalExecutor, SegmentReceipt, Session, SessionReceipt,
};
use sov_rollup_interface::zk::{ProofSystem, ZkVerifier, ZkvmHost};
#[cfg(feature = "bench")]
use zk_cycle_utils::{cycle_count_callback, get_syscall_name, get_syscall_name_cycles};

use crate::guest::Risc0Guest;
#[cfg(feature = "bench")]
use crate::metrics::metrics_callback;
use crate::Risc0MethodId;

pub struct Risc0Host<'a> {
    env: Mutex<Vec<u32>>,
    elf: &'a [u8],
}

#[cfg(not(feature = "bench"))]
fn add_benchmarking_callbacks<'env>(env: ExecutorEnvBuilder<'env>) -> ExecutorEnvBuilder<'env> {
    env
}

#[cfg(feature = "bench")]
fn add_benchmarking_callbacks<'env>(env: ExecutorEnvBuilder<'env>) -> ExecutorEnvBuilder<'env> {
    let metrics_syscall_name = get_syscall_name();
    env.io_callback(metrics_syscall_name, metrics_callback);

    let cycles_syscall_name = get_syscall_name_cycles();
    env.io_callback(cycles_syscall_name, cycle_count_callback);

    env
}

impl<'a> Risc0Host<'a> {
    pub fn new(elf: &'a [u8]) -> Self {
        Self {
            env: Default::default(),
            elf,
        }
    }

    /// Run a computation in the zkvm without generating a receipt.
    /// This creates the "Session" trace without invoking the heavy cryptographic machinery.
    pub fn run_without_proving(&mut self) -> anyhow::Result<Session> {
        let env = add_benchmarking_callbacks(ExecutorEnvBuilder::default())
            .add_input(&self.env.lock().unwrap())
            .build()
            .unwrap();
        let mut executor = LocalExecutor::from_elf(env, self.elf)?;
        executor.run()
    }

    /// Run a computation in the zkvm and generate a receipt.
    pub fn run(&mut self) -> anyhow::Result<SessionReceipt> {
        let session = self.run_without_proving()?;
        session.prove()
    }
}

impl<'a> ZkvmHost for Risc0Host<'a> {
    fn write_to_guest<T: serde::Serialize>(&self, item: T) {
        let serialized = to_vec(&item).expect("Serialization to vec is infallible");
        self.env.lock().unwrap().extend_from_slice(&serialized);
    }
}

pub struct Risc0Vm;

impl ZkVerifier for Risc0Vm {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }
}

impl ProofSystem for Risc0Vm {
    type Guest = Risc0Guest;
    type Host = Risc0Host<'static>;
}

impl<'host> ZkVerifier for Risc0Host<'host> {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }
}

fn verify_from_slice<'a>(
    serialized_proof: &'a [u8],
    code_commitment: &Risc0MethodId,
) -> Result<&'a [u8], anyhow::Error> {
    let Risc0Proof::<'a> {
        segment_receipts,
        journal,
        ..
    } = bincode::deserialize(serialized_proof)?;

    let receipts = segment_receipts
        .into_iter()
        .map(|r| r as Box<dyn Receipt>)
        .collect::<Vec<_>>();
    SessionReceipt::new(receipts, journal.to_vec()).verify(code_commitment.0)?;
    Ok(journal)
}

/// A convenience type which contains the same data a Risc0 [`SessionReceipt`] but borrows the journal
/// data. This allows to avoid one unnecessary copy during proof verification.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Risc0Proof<'a> {
    pub segment_receipts: Vec<Box<SegmentReceipt>>,
    pub journal: &'a [u8],
}
