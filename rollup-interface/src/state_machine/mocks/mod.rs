//! Defines mock instantiations of many important traits, which are useful
//! for testing, fuzzing, and benchmarking.

mod da;
#[cfg(all(feature = "native", feature = "tokio"))]
mod service;
mod validity_condition;
mod zk_vm;
pub use da::{
    MockAddress, MockBlob, MockBlock, MockBlockHeader, MockDaConfig, MockDaSpec, MockDaVerifier,
    MockHash, MOCK_SEQUENCER_DA_ADDRESS,
};
#[cfg(all(feature = "native", feature = "tokio"))]
pub use service::MockDaService;
pub use validity_condition::{MockValidityCond, MockValidityCondChecker};
pub use zk_vm::{MockCodeCommitment, MockProof, MockZkvm};
