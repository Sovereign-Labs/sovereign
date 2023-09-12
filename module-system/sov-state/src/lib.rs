//! Storage and state management interfaces for Sovereign SDK modules.

#![deny(missing_docs)]

pub mod codec;
mod internal_cache;

mod containers;
pub use containers::*;

#[cfg(feature = "native")]
mod prover_storage;

#[cfg(feature = "native")]
mod tree_db;

mod scratchpad;

/// Trait and type definitions related to the [`Storage`] trait.
pub mod storage;

mod utils;
mod witness;

mod zk_storage;

pub use zk_storage::ZkStorage;

pub mod config;

use std::fmt::Display;
use std::str;

#[cfg(feature = "native")]
pub use prover_storage::{delete_storage, ProverStorage};
pub use scratchpad::*;
pub use sov_first_read_last_write_cache::cache::CacheLog;
use sov_rollup_interface::digest::Digest;
pub use storage::Storage;
use utils::AlignedVec;

pub use crate::witness::{ArrayWitness, TreeWitnessReader, Witness};

/// A prefix prepended to each key before insertion and retrieval from the storage.
/// All the collection types in this crate are backed by the same storage instance, this means that insertions of the same key
/// to two different `StorageMaps` would collide with each other. We solve it by instantiating every collection type with a unique
/// prefix that is prepended to each key.
///
/// # Examples
///
/// ```
/// use sov_state::Prefix;
///
/// let prefix = Prefix::new(b"test".to_vec());
/// assert_eq!(prefix.len(), "4");
/// ```
#[derive(
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    Debug,
    PartialEq,
    Eq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Prefix {
    prefix: AlignedVec,
}

impl Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buf = self.prefix.as_ref();
        match str::from_utf8(buf) {
            Ok(s) => {
                write!(f, "{:?}", s)
            }
            Err(_) => {
                write!(f, "0x{}", hex::encode(buf))
            }
        }
    }
}

impl Prefix {
    /// Creates a new prefix from a byte vector.
    pub fn new(prefix: Vec<u8>) -> Self {
        Self {
            prefix: AlignedVec::new(prefix),
        }
    }

    /// Returns a reference to the internal [`AlignedVec`] used by this prefix.
    pub fn as_aligned_vec(&self) -> &AlignedVec {
        &self.prefix
    }

    /// Returns the length in bytes of the prefix.
    pub fn len(&self) -> usize {
        self.prefix.len()
    }

    /// Returns `true` if the prefix is empty, `false` otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefix.is_empty()
    }

    /// Returns a new prefix allocated on the fly, by extending the current
    /// prefix with the given bytes.
    pub fn extended(&self, bytes: &[u8]) -> Self {
        let mut prefix = self.clone();
        prefix.extend(bytes.iter().copied());
        prefix
    }
}

impl Extend<u8> for Prefix {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.prefix
            .extend(&AlignedVec::new(iter.into_iter().collect()))
    }
}

/// A trait specifying the hash function and format of the witness used in
/// merkle proofs for storage access
pub trait MerkleProofSpec {
    /// The structure that accumulates the witness data
    type Witness: Witness;
    /// The hash function used to compute the merkle root
    type Hasher: Digest<OutputSize = sha2::digest::typenum::U32>;
}

use sha2::Sha256;

/// The default [`MerkleProofSpec`] implementation.
///
/// This type is typically found as a type parameter for [`ProverStorage`].
#[derive(Clone)]
pub struct DefaultStorageSpec;

impl MerkleProofSpec for DefaultStorageSpec {
    type Witness = ArrayWitness;

    type Hasher = Sha256;
}
