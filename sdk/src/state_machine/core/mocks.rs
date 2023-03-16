use borsh::{BorshDeserialize, BorshSerialize};

use crate::zk::traits::{Matches, ProofTrait, ZkVm};

#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct MockCodeCommitment(pub [u8; 32]);

impl Matches<MockCodeCommitment> for MockCodeCommitment {
    fn matches(&self, other: &MockCodeCommitment) -> bool {
        self.0 == other.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct MockProof {
    program_id: MockCodeCommitment,
    log: Vec<u8>,
}

impl ProofTrait<MockZkvm> for MockProof {
    type Output = Vec<u8>;

    fn verify(self, code_commitment: &MockCodeCommitment) -> Result<Self::Output, anyhow::Error> {
        if !self.program_id.matches(code_commitment) {
            anyhow::bail!("Invalid code commitment")
        }
        Ok(self.log)
    }
}

pub struct MockZkvm;

impl ZkVm for MockZkvm {
    type CodeCommitment = MockCodeCommitment;

    type Proof = MockProof;

    type Error = anyhow::Error;

    fn write_to_guest<T: crate::serial::Encode>(_item: T) {
        todo!()
    }

    fn read_from_host<T: crate::serial::Decode>() -> T {
        todo!()
    }

    fn verify(
        _proof: Self::Proof,
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<<<Self as ZkVm>::Proof as crate::zk::traits::ProofTrait<Self>>::Output, Self::Error>
    {
        todo!()
    }
}
