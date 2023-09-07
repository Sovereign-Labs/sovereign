use super::StateKeyCodec;
use crate::codec::StateValueCodec;

/// A [`StateValueCodec`] that uses [`bcs`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct BcsCodec;

impl<K> StateKeyCodec<K> for BcsCodec
where
    K: serde::Serialize,
{
    fn encode_key(&self, key: &K) -> Vec<u8> {
        bcs::to_bytes(key).expect("Failed to serialize key")
    }
}

impl<V> StateValueCodec<V> for BcsCodec
where
    V: serde::Serialize + for<'a> serde::Deserialize<'a>,
{
    type Error = bcs::Error;

    fn encode_value(&self, value: &V) -> Vec<u8> {
        bcs::to_bytes(value).expect("Failed to serialize value")
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<V, Self::Error> {
        bcs::from_bytes(bytes)
    }
}
