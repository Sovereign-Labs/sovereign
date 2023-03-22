use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::serial::{Decode, Encode};

/// A proof that a program was executed in a zkVM.
pub trait ZkVm {
    type CodeCommitment: Matches<Self::CodeCommitment> + Clone;
    type Proof: ProofTrait<Self>;
    type Error: Debug;

    fn write_to_guest<T: Encode>(&self, item: T);
    fn read_from_host<T: Decode>(&self) -> T;
    fn verify(
        proof: Self::Proof,
        code_commitment: &Self::CodeCommitment,
    ) -> Result<<<Self as ZkVm>::Proof as ProofTrait<Self>>::Output, Self::Error>;
}

pub trait ProofTrait<VM: ZkVm + ?Sized> {
    type Output: Encode + Decode;
    /// Verify the proof, deserializing the result if successful.
    fn verify(self, code_commitment: &VM::CodeCommitment) -> Result<Self::Output, VM::Error>;
}

pub trait Matches<T> {
    fn matches(&self, other: &T) -> bool;
}

pub enum RecursiveProofInput<Vm: ZkVm, T, Pf: ProofTrait<Vm, Output = T>> {
    Base(T),
    Recursive(Pf, std::marker::PhantomData<Vm>),
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct RecursiveProofOutput<Vm: ZkVm, T> {
    pub claimed_method_id: Vm::CodeCommitment,
    pub output: T,
}

// TODO!
mod risc0 {
    #[allow(unused)]
    struct MethodId([u8; 32]);
}
