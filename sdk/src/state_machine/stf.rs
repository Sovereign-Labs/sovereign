use crate::maybestd::rc::Rc;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    core::traits::{BatchTrait, TransactionTrait},
    serial::{Decode, DecodeBorrowed},
};

/// An address on the DA layer. Opaque to the StateTransitionFunction
pub type OpaqueAddress = Rc<Vec<u8>>;

/// The configuration of a full node of the rollup which creates zk proofs.
pub struct ProverConfig;
/// The configuration used to intiailize the "Verifier" of the state transition function
/// which runs inside of the zkvm.
pub struct ZkConfig;
/// The configuration of a standard full node of the rollup which does not create zk proofs
pub struct StandardConfig;

pub trait StateTransitionConfig: sealed::Sealed {}
impl StateTransitionConfig for ProverConfig {}
impl StateTransitionConfig for ZkConfig {}
impl StateTransitionConfig for StandardConfig {}

mod sealed {
    use super::{ProverConfig, StandardConfig, ZkConfig};

    pub trait Sealed {}
    impl Sealed for ProverConfig {}
    impl Sealed for ZkConfig {}
    impl Sealed for StandardConfig {}
}

// TODO(@preston-evans98): update spec with simplified API
pub trait StateTransitionFunction {
    type StateRoot;
    /// The intial state of the rollup.
    type InitialState;

    type Transaction: TransactionTrait;
    /// A batch of transactions. Also known as a "block" in most systems: we use
    /// the term batch in this context to avoid ambiguity with DA layer blocks
    type Batch: BatchTrait<Transaction = Self::Transaction>;
    type Proof: Decode;

    /// A proof that the sequencer has misbehaved. For example, this could be a merkle proof of a transaction
    /// with an invalid signature
    type MisbehaviorProof;

    /// Perform one-time initialization for the genesis block.
    fn init_chain(&mut self, params: Self::InitialState);

    /// Called at the beginning of each DA-layer block - whether or not that block contains any
    /// data relevant to the rollup.
    fn begin_slot(&mut self);

    /// Apply a batch of transactions to the rollup, slashing the sequencer who proposed the batch on failure
    fn apply_batch(
        &mut self,
        batch: Self::Batch,
        sequencer: &[u8],
        misbehavior_hint: Option<Self::MisbehaviorProof>,
    ) -> anyhow::Result<Vec<Vec<Event>>>;

    fn apply_proof(
        &self,
        proof: Self::Proof,
        prover: &[u8],
    ) -> Result<(), ConsensusSetUpdate<OpaqueAddress>>;

    /// Called once at the *end* of each DA layer block (i.e. after all rollup batches and proofs have been processed)
    /// Commits state changes to the database
    fn end_slot(&mut self) -> (Self::StateRoot, Vec<ConsensusSetUpdate<OpaqueAddress>>);
}

pub trait StateTransitionRunner<T: StateTransitionConfig> {
    /// The parameters of the state transition function which are set at runtime. For example,
    /// the runtime config might contain path to a data directory.
    type RuntimeConfig;
    type Inner: StateTransitionFunction;
    // TODO: decide if `new` also requires <Self as StateTransitionFunction>::ChainParams as an argument
    /// Create a state transition runner
    fn new(runtime_config: Self::RuntimeConfig) -> Self;

    /// Return a reference to the inner STF implementation
    fn inner(&self) -> &Self::Inner;

    /// Return a mutable reference to the inner STF implementation
    fn inner_mut(&mut self) -> &mut Self::Inner;

    // /// Report if the state transition function has been initialized.
    // /// If not, node implementations should respond by running `init_chain`
    // fn has_been_initialized(&self) -> bool;
}

#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub enum ConsensusRole {
    Prover,
    Sequencer,
    ProverAndSequencer,
}

/// A key-value pair representing a change to the rollup state
#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Event {
    pub key: EventKey,
    pub value: EventValue,
}

impl Event {
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            key: EventKey(key.as_bytes().to_vec()),
            value: EventValue(value.as_bytes().to_vec()),
        }
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Serialize,
    Deserialize,
)]
pub struct EventKey(Vec<u8>);

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EventValue(Vec<u8>);

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ConsensusSetUpdate<Address> {
    pub address: Address,
    pub new_role: Option<ConsensusRole>,
}

impl ConsensusSetUpdate<OpaqueAddress> {
    pub fn slashing(sequencer: &[u8]) -> ConsensusSetUpdate<OpaqueAddress> {
        let faulty_sequencer = Rc::new(sequencer.to_vec());
        ConsensusSetUpdate {
            address: faulty_sequencer,
            new_role: None,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ConsensusMessage<B, P> {
    Batch(B),
    Proof(P),
}

#[derive(Debug, PartialEq, Clone)]
pub enum ConsensusMessageDecodeError<BatchErr, ProofErr> {
    Batch(BatchErr),
    Proof(ProofErr),
    NoTag,
    InvalidTag { max_allowed: u8, got: u8 },
}

impl<'de, P: DecodeBorrowed<'de>, B: DecodeBorrowed<'de>> DecodeBorrowed<'de>
    for ConsensusMessage<B, P>
{
    type Error = ConsensusMessageDecodeError<B::Error, P::Error>;
    fn decode_from_slice(target: &'de [u8]) -> Result<Self, Self::Error> {
        Ok(
            match *target
                .iter()
                .next()
                .ok_or(ConsensusMessageDecodeError::NoTag)?
            {
                0 => Self::Batch(
                    B::decode_from_slice(&target[1..])
                        .map_err(ConsensusMessageDecodeError::Batch)?,
                ),
                1 => Self::Proof(
                    P::decode_from_slice(&target[1..])
                        .map_err(ConsensusMessageDecodeError::Proof)?,
                ),
                _ => Err(ConsensusMessageDecodeError::InvalidTag {
                    max_allowed: 1,
                    got: target[0],
                })?,
            },
        )
    }
}
