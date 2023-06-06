// SPDX-License-Identifier: Apache-2.0
// Adapted from aptos-core/schemadb

#![forbid(unsafe_code)]

//! This library implements a schematized DB on top of [RocksDB](https://rocksdb.org/). It makes
//! sure all data passed in and out are structured according to predefined schemas and prevents
//! access to raw keys and values. This library also enforces a set of specific DB options,
//! like custom comparators and schema-to-column-family mapping.
//!
//! It requires that different kinds of key-value pairs be stored in separate column
//! families.  To use this library to store a kind of key-value pairs, the user needs to use the
//! [`define_schema!`] macro to define the schema name, the types of key and value, and name of the
//! column family.

use anyhow::{format_err, Result};
use iterator::{ScanDirection, SchemaIterator};
use metrics::{
    SCHEMADB_BATCH_COMMIT_BYTES, SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS,
    SCHEMADB_BATCH_PUT_LATENCY_SECONDS, SCHEMADB_DELETES, SCHEMADB_GET_BYTES,
    SCHEMADB_GET_LATENCY_SECONDS, SCHEMADB_PUT_BYTES,
};
use rocksdb::{ColumnFamilyDescriptor, ReadOptions};
use std::{collections::HashMap, path::Path, sync::Mutex};
use tracing::info;

pub use rocksdb::DEFAULT_COLUMN_FAMILY_NAME;
pub use sov_rollup_interface::db::Schema;
use sov_rollup_interface::db::{ColumnFamilyName, KeyCodec, ValueCodec};

pub mod iterator;
mod metrics;

#[cfg(test)]
mod db_test;
#[cfg(test)]
mod iterator_test;

#[derive(Debug)]
enum WriteOp {
    Value { key: Vec<u8>, value: Vec<u8> },
    Deletion { key: Vec<u8> },
}

/// `SchemaBatch` holds a collection of updates that can be applied to a DB atomically. The updates
/// will be applied in the order in which they are added to the `SchemaBatch`.
#[derive(Debug)]
pub struct SchemaBatch {
    rows: Mutex<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
}

impl Default for SchemaBatch {
    fn default() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
        }
    }
}

impl SchemaBatch {
    /// Creates an empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an insert/update operation to the batch.
    pub fn put<S: Schema>(&self, key: &impl KeyCodec<S>, value: &impl ValueCodec<S>) -> Result<()> {
        let _timer = SCHEMADB_BATCH_PUT_LATENCY_SECONDS
            .with_label_values(&["unknown"])
            .start_timer();
        let key = key.encode_key()?;
        let value = value.encode_value()?;
        self.rows
            .lock()
            .expect("Lock must not be poisoned")
            .entry(S::COLUMN_FAMILY_NAME)
            .or_insert_with(Vec::new)
            .push(WriteOp::Value { key, value });

        Ok(())
    }

    /// Adds a delete operation to the batch.
    pub fn delete<S: Schema>(&self, key: &impl KeyCodec<S>) -> Result<()> {
        let key = key.encode_key()?;
        self.rows
            .lock()
            .expect("Lock must not be poisoned")
            .entry(S::COLUMN_FAMILY_NAME)
            .or_insert_with(Vec::new)
            .push(WriteOp::Deletion { key });

        Ok(())
    }
}

/// This DB is a schematized RocksDB wrapper where all data passed in and out are typed according to
/// [`Schema`]s.
#[derive(Debug)]
pub struct DB {
    name: &'static str, // for logging
    inner: rocksdb::DB,
}

impl DB {
    /// Opens a database backed by rocksdb, using the provided column family names and default
    /// column family options.
    pub fn open(
        path: impl AsRef<Path>,
        name: &'static str,
        column_families: impl IntoIterator<Item = impl Into<String>>,
        db_opts: &rocksdb::Options,
    ) -> Result<Self> {
        let db = DB::open_cf(
            db_opts,
            path,
            name,
            column_families.into_iter().map(|cf_name| {
                let mut cf_opts = rocksdb::Options::default();
                cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
                rocksdb::ColumnFamilyDescriptor::new(cf_name, cf_opts)
            }),
        )?;
        Ok(db)
    }

    /// Open RocksDB with the provided column family descriptors
    pub fn open_cf(
        db_opts: &rocksdb::Options,
        path: impl AsRef<Path>,
        name: &'static str,
        cfds: impl IntoIterator<Item = ColumnFamilyDescriptor>,
    ) -> Result<DB> {
        let inner = rocksdb::DB::open_cf_descriptors(db_opts, path, cfds)?;
        Ok(Self::log_construct(name, inner))
    }

    /// Open db in readonly mode. This db is completely static, so any writes that occur on the primary
    /// after it has been opened will not be visible to the readonly instance.
    pub fn open_cf_readonly(
        opts: &rocksdb::Options,
        path: impl AsRef<Path>,
        name: &'static str,
        cfs: Vec<ColumnFamilyName>,
    ) -> Result<DB> {
        let error_if_log_file_exists = false;
        let inner = rocksdb::DB::open_cf_for_read_only(opts, path, cfs, error_if_log_file_exists)?;

        Ok(Self::log_construct(name, inner))
    }

    /// Open db in secondary mode. A secondary db is does not support writes, but can be dynamically caught up
    /// to the primary instance by a manual call. See https://github.com/facebook/rocksdb/wiki/Read-only-and-Secondary-instances
    /// for more details
    pub fn open_cf_as_secondary<P: AsRef<Path>>(
        opts: &rocksdb::Options,
        primary_path: P,
        secondary_path: P,
        name: &'static str,
        cfs: Vec<ColumnFamilyName>,
    ) -> Result<DB> {
        let inner = rocksdb::DB::open_cf_as_secondary(opts, primary_path, secondary_path, cfs)?;
        Ok(Self::log_construct(name, inner))
    }

    fn log_construct(name: &'static str, inner: rocksdb::DB) -> DB {
        info!(rocksdb_name = name, "Opened RocksDB.");
        DB { name, inner }
    }

    /// Reads single record by key.
    pub fn get<S: Schema>(&self, schema_key: &impl KeyCodec<S>) -> Result<Option<S::Value>> {
        let _timer = SCHEMADB_GET_LATENCY_SECONDS
            .with_label_values(&[S::COLUMN_FAMILY_NAME])
            .start_timer();

        let k = schema_key.encode_key()?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        let result = self.inner.get_cf(cf_handle, k)?;
        SCHEMADB_GET_BYTES
            .with_label_values(&[S::COLUMN_FAMILY_NAME])
            .observe(result.as_ref().map_or(0.0, |v| v.len() as f64));

        result
            .map(|raw_value| <S::Value as ValueCodec<S>>::decode_value(&raw_value))
            .transpose()
            .map_err(|err| err.into())
    }

    /// Writes single record.
    pub fn put<S: Schema>(&self, key: &impl KeyCodec<S>, value: &impl ValueCodec<S>) -> Result<()> {
        // Not necessary to use a batch, but we'd like a central place to bump counters.
        // Used in tests only anyway.
        let batch = SchemaBatch::new();
        batch.put::<S>(key, value)?;
        self.write_schemas(batch)
    }

    fn iter_with_direction<S: Schema>(
        &self,
        opts: ReadOptions,
        direction: ScanDirection,
    ) -> Result<SchemaIterator<S>> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        Ok(SchemaIterator::new(
            self.inner.raw_iterator_cf_opt(cf_handle, opts),
            direction,
        ))
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema with the default read options.
    pub fn iter<S: Schema>(&self) -> Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(Default::default(), ScanDirection::Forward)
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema with the provided read options.
    pub fn iter_with_opts<S: Schema>(&self, opts: ReadOptions) -> Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(opts, ScanDirection::Forward)
    }
    /// Returns a backward [`SchemaIterator`] on a certain schema with the default read options.
    pub fn rev_iter<S: Schema>(&self) -> Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(Default::default(), ScanDirection::Backward)
    }

    /// Returns a backward [`SchemaIterator`] on a certain schema with the provided read options.
    pub fn rev_iter_with_opts<S: Schema>(&self, opts: ReadOptions) -> Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(opts, ScanDirection::Backward)
    }

    /// Writes a group of records wrapped in a [`SchemaBatch`].
    pub fn write_schemas(&self, batch: SchemaBatch) -> Result<()> {
        let _timer = SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS
            .with_label_values(&[self.name])
            .start_timer();
        let rows_locked = batch.rows.lock().expect("Lock must not be poisoned");

        let mut db_batch = rocksdb::WriteBatch::default();
        for (cf_name, rows) in rows_locked.iter() {
            let cf_handle = self.get_cf_handle(cf_name)?;
            for write_op in rows {
                match write_op {
                    WriteOp::Value { key, value } => db_batch.put_cf(cf_handle, key, value),
                    WriteOp::Deletion { key } => db_batch.delete_cf(cf_handle, key),
                }
            }
        }
        let serialized_size = db_batch.size_in_bytes();

        self.inner.write_opt(db_batch, &default_write_options())?;

        // Bump counters only after DB write succeeds.
        for (cf_name, rows) in rows_locked.iter() {
            for write_op in rows {
                match write_op {
                    WriteOp::Value { key, value } => {
                        SCHEMADB_PUT_BYTES
                            .with_label_values(&[cf_name])
                            .observe((key.len() + value.len()) as f64);
                    }
                    WriteOp::Deletion { key: _ } => {
                        SCHEMADB_DELETES.with_label_values(&[cf_name]).inc();
                    }
                }
            }
        }
        SCHEMADB_BATCH_COMMIT_BYTES
            .with_label_values(&[self.name])
            .observe(serialized_size as f64);

        Ok(())
    }

    fn get_cf_handle(&self, cf_name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.inner.cf_handle(cf_name).ok_or_else(|| {
            format_err!(
                "DB::cf_handle not found for column family name: {}",
                cf_name
            )
        })
    }

    /// Flushes memtable data. This is only used for testing `get_approximate_sizes_cf` in unit
    /// tests.
    pub fn flush_cf(&self, cf_name: &str) -> Result<()> {
        Ok(self.inner.flush_cf(self.get_cf_handle(cf_name)?)?)
    }

    /// Returns the current rocksdb property value for the provided column family name
    /// and property name
    pub fn get_property(&self, cf_name: &str, property_name: &str) -> Result<u64> {
        self.inner
            .property_int_value_cf(self.get_cf_handle(cf_name)?, property_name)?
            .ok_or_else(|| {
                format_err!(
                    "Unable to get property \"{}\" of  column family \"{}\".",
                    property_name,
                    cf_name,
                )
            })
    }

    /// Creates new physical DB checkpoint in directory specified by `path`.
    pub fn create_checkpoint<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        rocksdb::checkpoint::Checkpoint::new(&self.inner)?.create_checkpoint(path)?;
        Ok(())
    }
}

/// For now we always use synchronous writes. This makes sure that once the operation returns
/// `Ok(())` the data is persisted even if the machine crashes. In the future we might consider
/// selectively turning this off for some non-critical writes to improve performance.
fn default_write_options() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    opts
}

#[cfg(any(test, feature = "temppath"))]
pub mod temppath {
    // Adapted from aptos temppath

    use rand::RngCore;
    use std::{
        fs, io,
        path::{Path, PathBuf},
    };

    /// A simple wrapper for creating a temporary directory that is automatically deleted when it's
    /// dropped. Used in lieu of tempfile due to the large number of dependencies.
    #[derive(Debug, PartialEq, Eq)]
    pub struct TempPath {
        path_buf: PathBuf,
        persist: bool,
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            if !self.persist {
                fs::remove_dir_all(&self.path_buf)
                    .or_else(|_| fs::remove_file(&self.path_buf))
                    .unwrap_or(());
            }
        }
    }

    impl TempPath {
        /// Create new, uninitialized temporary path in the system temp directory.
        pub fn new() -> Self {
            Self::new_with_temp_dir(std::env::temp_dir())
        }

        /// Create new, uninitialized temporary path in the specified directory.
        pub fn new_with_temp_dir(temp_dir: PathBuf) -> Self {
            let mut temppath = temp_dir;
            let mut rng = rand::thread_rng();
            let mut bytes = [0_u8; 16];
            rng.fill_bytes(&mut bytes);
            temppath.push(hex::encode(bytes));

            TempPath {
                path_buf: temppath,
                persist: false,
            }
        }

        /// Return the underlying path to this temporary directory.
        pub fn path(&self) -> &Path {
            &self.path_buf
        }

        /// Keep the temp path
        pub fn persist(&mut self) {
            self.persist = true;
        }

        pub fn create_as_file(&self) -> io::Result<()> {
            let mut builder = fs::OpenOptions::new();
            builder.write(true).create_new(true);
            builder.open(self.path())?;
            Ok(())
        }

        pub fn create_as_dir(&self) -> io::Result<()> {
            let builder = fs::DirBuilder::new();
            builder.create(self.path())?;
            Ok(())
        }
    }

    impl AsRef<Path> for TempPath {
        fn as_ref(&self) -> &Path {
            self.path()
        }
    }

    impl Default for TempPath {
        fn default() -> Self {
            Self::new()
        }
    }
}
