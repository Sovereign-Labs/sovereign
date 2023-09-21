use std::io::Write;

use anyhow::ensure;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::zk::{Matches, Zkvm};

/// A mock commitment to a particular zkVM program.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct MockCodeCommitment(pub [u8; 32]);

impl Matches<MockCodeCommitment> for MockCodeCommitment {
    fn matches(&self, other: &MockCodeCommitment) -> bool {
        self.0 == other.0
    }
}

/// A mock proof generated by a zkVM.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct MockProof<'a> {
    /// The ID of the program this proof might be valid for.
    pub program_id: MockCodeCommitment,
    /// Whether the proof is valid.
    pub is_valid: bool,
    /// The tamper-proof outputs of the proof.
    pub log: &'a [u8],
}

impl<'a> MockProof<'a> {
    /// Serializes a proof into a writer.
    pub fn encode(&self, mut writer: impl Write) {
        writer.write_all(&self.program_id.0).unwrap();
        let is_valid_byte = if self.is_valid { 1 } else { 0 };
        writer.write_all(&[is_valid_byte]).unwrap();
        writer.write_all(self.log).unwrap();
    }

    /// Serializes a proof into a vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        self.encode(&mut encoded);
        encoded
    }

    /// Tries to deserialize a proof from a byte slice.
    pub fn decode(input: &'a [u8]) -> Result<Self, anyhow::Error> {
        ensure!(input.len() >= 33, "Input is too short");
        let program_id = MockCodeCommitment(input[0..32].try_into().unwrap());
        let is_valid = input[32] == 1;
        let log = &input[33..];
        Ok(Self {
            program_id,
            is_valid,
            log,
        })
    }
}

/// A mock implementing the zkVM trait.
pub struct MockZkvm;

impl Zkvm for MockZkvm {
    type CodeCommitment = MockCodeCommitment;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        let proof = MockProof::decode(serialized_proof)?;
        anyhow::ensure!(
            proof.program_id.matches(code_commitment),
            "Proof failed to verify against requested code commitment"
        );
        anyhow::ensure!(proof.is_valid, "Proof is not valid");
        Ok(proof.log)
    }

    fn verify_and_extract_output<
        Add: crate::RollupAddress,
        Da: crate::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<crate::zk::StateTransition<Da, Add, Root>, Self::Error> {
        let output = Self::verify(serialized_proof, code_commitment)?;
        Ok(bincode::deserialize(output)?)
    }
}

#[test]
fn test_mock_proof_roundtrip() {
    let proof = MockProof {
        program_id: MockCodeCommitment([1; 32]),
        is_valid: true,
        log: &[2; 50],
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    let decoded = MockProof::decode(&encoded).unwrap();
    assert_eq!(proof, decoded);
}
