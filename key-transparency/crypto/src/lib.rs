use ed25519_dalek as dalek;
use ed25519_dalek::{Signer, Verifier};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

/// Convenient name for Dalek's signature error.
pub type CryptoError = dalek::SignatureError;

/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Convert a digest into a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Return the number of bytes of a digest.
    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// Represents the public key (and identity) of the IdP or witness.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash)]
pub struct PublicKey(pub [u8; dalek::PUBLIC_KEY_LENGTH]);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKey {
    /// Encode a public key in base64 (human-readable).
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    /// Decode a base64-encoded public key.
    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

/// Represents a public and secret key pair.
/// TODO: Make sure secrets are not copyable and movable to control where they are in memory
pub struct KeyPair(dalek::Keypair);

impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&base64::encode(&self.0.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<KeyPair, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = base64::decode(&s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
        let key = dalek::Keypair::from_bytes(&value)
            .map_err(|err| serde::de::Error::custom(err.to_string()))?;
        Ok(KeyPair(key))
    }
}

impl KeyPair {
    /// Returns the public key part of the keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public.to_bytes())
    }

    /// Generate a new keypair.
    pub fn generate_production_keypair() -> (PublicKey, KeyPair) {
        Self::generate_keypair(&mut OsRng)
    }

    /// Generate a keypair from the specified RNG (useful for testing).
    pub fn generate_keypair<R>(csprng: &mut R) -> (PublicKey, KeyPair)
    where
        R: CryptoRng + RngCore,
    {
        let keypair = dalek::Keypair::generate(csprng);
        (PublicKey(keypair.public.to_bytes()), KeyPair(keypair))
    }
}

/// A signature over a digest.
#[derive(Serialize, Deserialize, Clone)]
pub struct Signature(dalek::Signature);

impl Default for Signature {
    fn default() -> Self {
        Self(dalek::Signature::from_bytes(&[0; dalek::SIGNATURE_LENGTH]).unwrap())
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = base64::encode(&self.0);
        write!(f, "{}", s)?;
        Ok(())
    }
}

impl Signature {
    /// Sign a digest with the specified private key.
    pub fn new(value: &Digest, secret: &KeyPair) -> Self {
        Signature(secret.0.sign(value.as_ref()))
    }

    /// Verify a (single) signature over a digest.
    pub fn verify(&self, value: &Digest, author: &PublicKey) -> Result<(), CryptoError> {
        let public_key = dalek::PublicKey::from_bytes(author.as_ref())?;
        public_key.verify(value.as_ref(), &self.0)
    }

    /// Batch-verify many signature4d over the same digest.
    pub fn verify_batch<'a, I>(value: &'a Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let mut messages: Vec<&[u8]> = Vec::new();
        let mut signatures: Vec<dalek::Signature> = Vec::new();
        let mut public_keys: Vec<dalek::PublicKey> = Vec::new();
        for (addr, sig) in votes.into_iter() {
            messages.push(value.as_ref());
            signatures.push(sig.0);
            public_keys.push(dalek::PublicKey::from_bytes(&addr.0)?);
        }
        dalek::verify_batch(&messages[..], &signatures[..], &public_keys[..])
    }
}
