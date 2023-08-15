//! Serialization and deserialization -related logic.

use std::borrow::Borrow;
use std::rc::Rc;
use std::sync::Arc;

pub trait StateKeyEncode<K: ?Sized> {
    /// Serializes a key into a bytes vector.
    ///
    /// This method **must** not panic as all instances of the key type are
    /// supposed to be serializable.
    fn encode_key(&self, key: &K) -> Vec<u8>;
}

/// A trait for types that can serialize and deserialize keys for storage
/// access.
pub trait StateKeyCodec<K>: StateKeyEncode<K> {
    /// Error type that can arise during deserialization.
    type KeyError: std::fmt::Debug;

    /// Tries to deserialize a key from a bytes slice, and returns a
    /// [`Result`] with either the deserialized key or an error.
    fn try_decode_key(&self, bytes: &[u8]) -> Result<K, Self::KeyError>;

    /// Deserializes a key from a bytes slice.
    ///
    /// # Panics
    /// Panics if the call to [`StateKeyCodec::try_decode_key`] fails. Use
    /// [`StateKeyCodec::try_decode_key`] if you need to gracefully handle
    /// errors.
    fn decode_key(&self, bytes: &[u8]) -> K {
        self.try_decode_key(bytes)
            .map_err(|err| {
                format!(
                    "Failed to decode key 0x{}, error: {:?}",
                    hex::encode(bytes),
                    err
                )
            })
            .unwrap()
    }
}

pub trait StateKeyEncodePreservingBorrow<Borrower, Borrowed>
where
    Borrowed: ?Sized,
    Borrower: Borrow<Borrowed>,
    Self: StateKeyEncode<Borrower> + StateKeyEncode<Borrowed>,
{
}

/// A trait for types that can serialize and deserialize values for storage
/// access.
pub trait StateValueCodec<V> {
    /// Error type that can arise during deserialization.
    type ValueError: std::fmt::Debug;

    /// Serializes a value into a bytes vector.
    ///
    /// This method **must** not panic as all instances of the value type are
    /// supposed to be serializable.
    fn encode_value(&self, value: &V) -> Vec<u8>;

    /// Tries to deserialize a value from a bytes slice, and returns a
    /// [`Result`] with either the deserialized value or an error.
    fn try_decode_value(&self, bytes: &[u8]) -> Result<V, Self::ValueError>;

    /// Deserializes a value from a bytes slice.
    ///
    /// # Panics
    /// Panics if the call to [`StateValueCodec::try_decode_value`] fails. Use
    /// [`StateValueCodec::try_decode_value`] if you need to gracefully handle
    /// errors.
    fn decode_value(&self, bytes: &[u8]) -> V {
        self.try_decode_value(bytes)
            .map_err(|err| {
                format!(
                    "Failed to decode value 0x{}, error: {:?}",
                    hex::encode(bytes),
                    err
                )
            })
            .unwrap()
    }
}

/// A market trait for types that implement both [`StateKeyCodec`] and
/// [`StateValueCodec`].
///
/// This trait is blanket-implemented for all types that implement both of the
/// above.
pub trait StateCodec<K, V>: StateKeyCodec<K> + StateValueCodec<V> {}

impl<K, V, C> StateCodec<K, V> for C where C: StateKeyCodec<K> + StateValueCodec<V> {}

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize)]
pub struct BorshCodec;

impl<K> StateKeyEncode<K> for BorshCodec
where
    K: ?Sized + borsh::BorshSerialize,
{
    fn encode_key(&self, key: &K) -> Vec<u8> {
        key.try_to_vec().expect("Failed to serialize key")
    }
}

impl<K> StateKeyCodec<K> for BorshCodec
where
    K: borsh::BorshSerialize + borsh::BorshDeserialize,
{
    type KeyError = std::io::Error;

    fn try_decode_key(&self, bytes: &[u8]) -> Result<K, Self::KeyError> {
        K::try_from_slice(bytes)
    }
}

impl<V> StateValueCodec<V> for BorshCodec
where
    V: borsh::BorshSerialize + borsh::BorshDeserialize,
{
    type ValueError = std::io::Error;

    fn encode_value(&self, value: &V) -> Vec<u8> {
        value.try_to_vec().expect("Failed to serialize value")
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<V, Self::ValueError> {
        V::try_from_slice(bytes)
    }
}

impl<K> StateKeyEncodePreservingBorrow<K, K> for BorshCodec where K: borsh::BorshSerialize {}
impl<K> StateKeyEncodePreservingBorrow<Arc<K>, K> for BorshCodec where K: borsh::BorshSerialize {}
impl<K> StateKeyEncodePreservingBorrow<Box<K>, K> for BorshCodec where K: borsh::BorshSerialize {}
impl<K> StateKeyEncodePreservingBorrow<Rc<K>, K> for BorshCodec where K: borsh::BorshSerialize {}
// Note: we're specifically *not* implementing it for `<[u8; _], [u8]>` because
// arrays and slices have different representations in Borsh.
impl<K> StateKeyEncodePreservingBorrow<Vec<K>, [K]> for BorshCodec where K: borsh::BorshSerialize {}

/// A [`StateCodec`] that uses two different codecs under the hood, one for keys
/// and one for values.
pub struct PairOfCodecs<KC, VC> {
    pub key_codec: KC,
    pub value_codec: VC,
}

impl<K, KC, VC> StateKeyEncode<K> for PairOfCodecs<KC, VC>
where
    K: ?Sized,
    KC: StateKeyEncode<K>,
{
    fn encode_key(&self, key: &K) -> Vec<u8> {
        self.key_codec.encode_key(key)
    }
}

impl<K, KC, VC> StateKeyCodec<K> for PairOfCodecs<KC, VC>
where
    KC: StateKeyCodec<K>,
{
    type KeyError = KC::KeyError;

    fn decode_key(&self, bytes: &[u8]) -> K {
        self.key_codec.decode_key(bytes)
    }

    fn try_decode_key(&self, bytes: &[u8]) -> Result<K, Self::KeyError> {
        self.key_codec.try_decode_key(bytes)
    }
}

impl<V, KC, VC> StateValueCodec<V> for PairOfCodecs<KC, VC>
where
    VC: StateValueCodec<V>,
{
    type ValueError = VC::ValueError;

    fn decode_value(&self, bytes: &[u8]) -> V {
        self.value_codec.decode_value(bytes)
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<V, Self::ValueError> {
        self.value_codec.try_decode_value(bytes)
    }

    fn encode_value(&self, value: &V) -> Vec<u8> {
        self.value_codec.encode_value(value)
    }
}

impl<K, Q, KC, VC> StateKeyEncodePreservingBorrow<K, Q> for PairOfCodecs<KC, VC>
where
    Q: ?Sized,
    K: Borrow<Q>,
    KC: StateKeyEncodePreservingBorrow<K, Q>,
{
}
