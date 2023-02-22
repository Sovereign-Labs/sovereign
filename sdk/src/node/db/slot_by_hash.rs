use super::{ColumnFamilyName, KeyDecoder, Schema, ValueCodec};
use super::{KeyEncoder, Result};
use std::fmt::Debug;

use crate::da::BlockHashTrait;
use crate::{serial::Decode, services::da::SlotData};

pub const SLOT_BY_HASH_CF_NAME: ColumnFamilyName = "slot_by_hash";

#[derive(Debug)]
pub struct SlotByHashSchema<K, V>(std::marker::PhantomData<K>, std::marker::PhantomData<V>);

impl<K, V> Schema for SlotByHashSchema<K, V>
where
    K: Debug + Send + Sync + 'static + BlockHashTrait,
    V: Debug + Send + Sync + 'static + SlotData,
{
    type Key = K;
    type Value = V;

    const COLUMN_FAMILY_NAME: ColumnFamilyName = SLOT_BY_HASH_CF_NAME;
}

impl<K, V> KeyEncoder<SlotByHashSchema<K, V>> for K
where
    K: Debug + Send + Sync + 'static + BlockHashTrait,
    V: Debug + Send + Sync + 'static + SlotData,
{
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.encode_to_vec())
    }
}

impl<K, V> KeyDecoder<SlotByHashSchema<K, V>> for K
where
    K: Debug + Send + Sync + 'static + BlockHashTrait,
    V: Debug + Send + Sync + 'static + SlotData,
{
    fn decode_key(mut data: &[u8]) -> Result<Self> {
        Ok(K::decode(&mut data)?)
    }
}

impl<K, V> ValueCodec<SlotByHashSchema<K, V>> for V
where
    K: Debug + Send + Sync + 'static + BlockHashTrait,
    V: Debug + Send + Sync + 'static + SlotData,
{
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(self.encode_to_vec())
    }

    fn decode_value(mut data: &[u8]) -> Result<Self> {
        Ok(<V as Decode>::decode(&mut data)?)
    }
}
