pub mod app;
#[cfg(feature = "native")]
pub mod genesis_config;
#[cfg(feature = "native")]
pub mod runner_config;
pub mod runtime;
#[cfg(test)]
pub mod tests;
pub mod tx_hooks_impl;

#[cfg(feature = "native")]
use sov_modules_api::{
    default_context::DefaultContext,
    default_signature::{private_key::DefaultPrivateKey, DefaultSignature},
    Hasher, Spec,
};

pub use sov_state::ArrayWitness;

#[cfg(feature = "native")]
pub fn sign_tx(priv_key: &DefaultPrivateKey, message: &[u8], nonce: u64) -> DefaultSignature {
    let mut hasher = <DefaultContext as Spec>::Hasher::new();
    hasher.update(message);
    hasher.update(&nonce.to_le_bytes());
    let msg_hash = hasher.finalize();
    priv_key.sign(msg_hash)
}
