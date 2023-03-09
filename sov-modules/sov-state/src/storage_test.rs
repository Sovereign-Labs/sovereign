use sha2::Sha256;

use crate::{
    storage::{StorageKey, StorageValue},
    tree_db::ZkTreeDb,
    JmtStorage, Storage, ZkStorage,
};

#[test]
fn test_value_absent_in_zk_storage() {
    let key = StorageKey::from("key");
    let value = StorageValue::from("value");

    let path = schemadb::temppath::TempPath::new();
    let zk_db: ZkTreeDb = {
        let mut storage = JmtStorage::<Sha256>::with_path(&path).unwrap();
        storage.set(key.clone(), value.clone());
        storage.merge();
        storage.finalize();
        storage.take_treedb_log()
    }
    .expect("Read log must be populated")
    .into();

    {
        let mut storage = JmtStorage::<Sha256>::with_path(&path).unwrap();
        storage.get(key.clone());
        storage.merge();

        let reads = storage.get_first_reads();

        // Here we crate a new ZkStorage with an empty inner cache.
        let storage = ZkStorage::<Sha256>::new(reads, zk_db);
        // `storage.get` tries to fetch the value from the (empty) inner cache but it fails,
        // then it fallbacks to the `reads` we provided in the constructor of the ZkStorage.
        let retrieved_value = storage.get(key);
        assert_eq!(Some(value), retrieved_value);
    }
}
