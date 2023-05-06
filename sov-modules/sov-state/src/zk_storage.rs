use std::sync::Arc;

use jmt::{JellyfishMerkleTree, KeyHash, PhantomHasher, SimpleHasher, Version};
use sovereign_sdk::core::traits::{TreeWitnessReader, Witness};

use crate::{
    internal_cache::StorageInternalCache,
    storage::{StorageKey, StorageValue},
    MerkleProofSpec, Storage,
};

pub struct ZkStorage<S: MerkleProofSpec> {
    prev_state_root: [u8; 32],
    _phantom_hasher: PhantomHasher<S::Hasher>,
}

impl<S: MerkleProofSpec> Clone for ZkStorage<S> {
    fn clone(&self) -> Self {
        Self {
            prev_state_root: self.prev_state_root,
            _phantom_hasher: Default::default(),
        }
    }
}

impl<S: MerkleProofSpec> ZkStorage<S> {
    pub fn new(prev_state_root: [u8; 32]) -> Self {
        Self {
            prev_state_root,
            _phantom_hasher: Default::default(),
        }
    }
}

impl<S: MerkleProofSpec> Storage for ZkStorage<S> {
    type Witness = S::Witness;

    type RuntimeConfig = [u8; 32];

    fn with_config(config: Self::RuntimeConfig) -> Result<Self, anyhow::Error> {
        Ok(Self::new(config))
    }

    fn get(&self, _key: StorageKey, witness: &S::Witness) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn validate_and_commit(
        &self,
        cache_log: StorageInternalCache,
        witness: &Self::Witness,
    ) -> Result<[u8; 32], anyhow::Error> {
        let latest_version: Version = witness.get_hint();
        let (_, writes) = cache_log.tx_cache.split();
        let reader = TreeWitnessReader::new(witness);

        // For each value that's been read from the tree, verify the provided smt proof
        for (key, read_value) in cache_log.ordered_db_reads.into_iter() {
            // TODO: Remove
            println!(
                "validating read in zk. key: {:?}, value:{:?} ",
                hex::encode(key.key.as_ref()),
                read_value.clone().map(|v| hex::encode(v.value.as_ref()))
            );
            let key_hash = KeyHash(S::Hasher::hash(key.key.as_ref()));
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<S::Hasher> = witness.get_hint();
            match read_value {
                Some(val) => proof.verify_existence(
                    jmt::RootHash(self.prev_state_root),
                    key_hash,
                    val.value.as_ref(),
                )?,
                None => proof.verify_nonexistence(jmt::RootHash(self.prev_state_root), key_hash)?,
            }
        }

        // Compute the jmt update from the write batch
        let batch = writes.into_iter().map(|(key, value)| {
            let key_hash = KeyHash(S::Hasher::hash(key.key.as_ref()));
            (
                key_hash,
                value.map(|v| Arc::try_unwrap(v.value).unwrap_or_else(|arc| (*arc).clone())),
            )
        });

        let next_version = latest_version + 1;
        // TODO: Make updates verifiable. Currently, writes don't verify that the provided siblings existed in the old tree
        // because the TreeReader is trusted
        let jmt = JellyfishMerkleTree::<_, S::Hasher>::new(&reader);

        let (new_root, _tree_update) = jmt
            .put_value_set(batch, next_version)
            .expect("JMT update must succeed");

        Ok(new_root.0)
    }
}
