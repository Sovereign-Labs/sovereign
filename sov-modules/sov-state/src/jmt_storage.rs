use crate::storage::{Storage, StorageKey, StorageValue};
use first_read_last_write_cache::cache::CacheLog;
use jellyfish_merkle_generic::Version;

// Storage backed by JMT.
pub struct JmtStorage {
    // Caches first read and last write for a particular key.
    _cache: CacheLog,
}

impl Storage for JmtStorage {
    fn get(&mut self, _key: StorageKey, _version: Version) -> Option<StorageValue> {
        todo!()
    }

    fn set(&mut self, _key: StorageKey, _version: Version, _value: StorageValue) {
        todo!()
    }

    fn delete(&mut self, _key: StorageKey, _version: u64) {
        todo!()
    }
}
