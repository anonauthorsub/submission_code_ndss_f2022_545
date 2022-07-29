use crate::{deserialize_root, serialize_root, Root, SequenceNumber};
use vkd::errors::AkdError;
use crypto::{CryptoError, Digest, PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

/// Convenient result wrappers.
pub type MessageResult<T> = Result<T, MessageError>;
pub type WitnessResult<T> = Result<T, WitnessError>;
pub type IdpResult<T> = Result<T, IdpError>;

/// Errors triggered when parsing and verifying protocol messages.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum MessageError {
    #[error("Malformed notification id {0}")]
    MalformedNotificationId(Digest),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Message signed by unknown witness {0}")]
    UnknownWitness(PublicKey),

    #[error("Witness {0} appears in quorum more than once")]
    WitnessReuse(PublicKey),

    #[error("Received certificate without a quorum")]
    CertificateRequiresQuorum,

    #[error("Failed to deserialize message ({0})")]
    SerializationError(String),

    #[error("State proof verification failed: {0}")]
    PoofVerificationFailed(String),

    #[error("The update request is too short (min 2 bytes)")]
    UpdateRequestTooShort,
}

impl From<CryptoError> for MessageError {
    fn from(error: CryptoError) -> Self {
        MessageError::InvalidSignature(error.to_string())
    }
}

impl From<Box<bincode::ErrorKind>> for MessageError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        MessageError::SerializationError(error.to_string())
    }
}

impl From<AkdError> for MessageError {
    fn from(error: AkdError) -> Self {
        MessageError::PoofVerificationFailed(error.to_string())
    }
}

/// Errors triggered by the witness when processing IdP's messages.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum WitnessError {
    #[error(transparent)]
    MessageError(#[from] MessageError),

    #[error("Received unexpected sequence number, expected {expected} but got {got}")]
    UnexpectedSequenceNumber {
        expected: SequenceNumber,
        got: SequenceNumber,
    },

    #[error("Received conflicting notifications: {lock:?} != {received:?}")]
    ConflictingNotification {
        #[serde(serialize_with = "serialize_root")]
        #[serde(deserialize_with = "deserialize_root")]
        lock: Root,
        #[serde(serialize_with = "serialize_root")]
        #[serde(deserialize_with = "deserialize_root")]
        received: Root,
    },

    #[error("Missing earlier certificates, current sequence number at {0}")]
    MissingEarlierCertificates(SequenceNumber),
}

/// Errors triggered by the IdP.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum IdpError {
    #[error(transparent)]
    MessageError(#[from] MessageError),

    #[error(transparent)]
    WitnessError(#[from] WitnessError),

    #[error("Received unexpected protocol message")]
    UnexpectedProtocolMessage,

    #[error("Received unexpected vote: {expected:?} != {received:?}")]
    UnexpectedVote {
        #[serde(serialize_with = "serialize_root")]
        #[serde(deserialize_with = "deserialize_root")]
        expected: Root,
        #[serde(serialize_with = "serialize_root")]
        #[serde(deserialize_with = "deserialize_root")]
        received: Root,
    },
}
