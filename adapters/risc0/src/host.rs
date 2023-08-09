use std::cell::RefCell;

use risc0_zkvm::receipt::Receipt;
use risc0_zkvm::serde::to_vec;
use risc0_zkvm::{
    Executor, ExecutorEnvBuilder, LocalExecutor, SegmentReceipt, Session, SessionReceipt,
};
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_rollup_interface::AddressTrait;

use crate::Risc0MethodId;

pub struct Risc0Host<'a> {
    env: RefCell<ExecutorEnvBuilder<'a>>,
    elf: &'a [u8],
}

impl<'a> Risc0Host<'a> {
    pub fn new(elf: &'a [u8]) -> Self {
        Self {
            env: RefCell::new(ExecutorEnvBuilder::default()),
            elf,
        }
    }

    /// Run a computation in the zkvm without generating a receipt.
    /// This creates the "Session" trace without invoking the heavy cryptographic machinery.
    pub fn run_without_proving(&mut self) -> anyhow::Result<Session> {
        let env = self.env.borrow_mut().build()?;
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
        self.env.borrow_mut().add_input(&serialized);
    }
}

impl<'prover> Zkvm for Risc0Host<'prover> {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }

    fn verify_and_extract_output<
        C: sov_rollup_interface::zk::ValidityCondition,
        Add: AddressTrait,
    >(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<C, Add>, Self::Error> {
        todo!("Implement once risc0 supports recursion, issue #633")
    }
}

pub struct Risc0Verifier;

impl Zkvm for Risc0Verifier {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }

    fn verify_and_extract_output<
        C: sov_rollup_interface::zk::ValidityCondition,
        Add: AddressTrait,
    >(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<C, Add>, Self::Error> {
        // Method to implement: not clear how to deserialize the proof output.
        // Issue #621.
        todo!("not clear how to deserialize the proof output. Issue #621")
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
