use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sov_rollup_interface::{
    anyhow,
    zk::{Matches, Zkvm},
};
#[cfg(feature = "native")]
pub use sp1_core;
#[cfg(feature = "native")]
use sp1_core::utils::BabyBearBlake3;
pub use sp1_zkvm;
use spec::Sp1CryptoSpec;
pub mod crypto;

pub mod guest;
#[cfg(feature = "native")]
pub mod host;
pub mod spec;

/// A commitment to the binary being proven. For Sp1, this
/// is currently the entire ELF file.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sp1CodeCommitment(Vec<u8>);

impl Matches<Sp1CodeCommitment> for Sp1CodeCommitment {
    fn matches(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Sp1CodeCommitment {
    pub fn from_elf(elf: &[u8]) -> Self {
        Self(elf.to_vec())
    }
}

/// A verifier for Risc0 proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sp1Verifier;

#[cfg(feature = "native")]
impl Zkvm for Sp1Verifier {
    type CodeCommitment = Sp1CodeCommitment;

    type CryptoSpec = Sp1CryptoSpec;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        let proof: sp1_core::SP1ProofWithIO<BabyBearBlake3> =
            bincode::deserialize(serialized_proof)?;
        sp1_core::SP1Verifier::verify(&code_commitment.0, &proof)
            .map_err(|e| anyhow::anyhow!("Sp1 verification failed. Error: {:?}", e))?;

        Ok(proof.stdout.buffer.data)
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let mut proof: sp1_core::SP1ProofWithIO<BabyBearBlake3> =
            bincode::deserialize(serialized_proof)?;
        sp1_core::SP1Verifier::verify(&code_commitment.0, &proof)
            .map_err(|e| anyhow::anyhow!("Sp1 verification failed. Error: {:?}", e))?;
        Ok(proof.stdout.read())
    }
}

#[cfg(not(feature = "native"))]
impl Zkvm for Sp1Verifier {
    type CodeCommitment = Sp1CodeCommitment;

    type CryptoSpec = Sp1CryptoSpec;

    type Error = anyhow::Error;

    fn verify<'a>(
        _serialized_proof: &'a [u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        todo!("This will be implemented once sp1 supports recursion")
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        todo!("This will be implemented once sp1 supports recursion")
    }
}
