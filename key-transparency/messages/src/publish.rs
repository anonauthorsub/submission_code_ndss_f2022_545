use crate::{
    deserialize_root, ensure,
    error::{MessageError, MessageResult},
    serialize_root, Blake3, Root, SequenceNumber,
};
use vkd::proof_structs::AppendOnlyProof;
use config::Committee;
use crypto::{Digest, KeyPair, PublicKey, Signature};
use ed25519_dalek::{Digest as _, Sha512};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryInto};
use winter_crypto::Digest as _;

/// Represents a state proof.
pub type Proof = AppendOnlyProof<Blake3>;

/// A message that can be hashed.
pub trait PublishMessage {
    /// Return a reference to the root commitment.
    fn root(&self) -> &Root;

    /// Return the sequence number of the message.
    fn sequence_number(&self) -> SequenceNumber;

    /// Compute the hash of the message.
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.root().as_bytes());
        hasher.update(self.sequence_number().to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

/// An publish notification sent by the IdP to the witnesses to request votes.
#[derive(Serialize, Deserialize, Clone)]
pub struct PublishNotification {
    /// The root committing to the new state.
    #[serde(serialize_with = "serialize_root")]
    #[serde(deserialize_with = "deserialize_root")]
    pub root: Root,
    /// The state-transition proof ensuring the published state is valid.
    pub proof: Proof,
    /// The sequence number unique to this publish notification.
    pub sequence_number: SequenceNumber,
    /// The hash of the previous fields of this publish.
    pub id: Digest,
    /// A signature from the IdP authenticating the publish.
    pub signature: Signature,
}

impl std::fmt::Debug for PublishNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}: N{}({})",
            self.id,
            self.sequence_number,
            base64::encode(self.root.as_bytes())
        )
    }
}

// Useful for tests.
impl PartialEq for PublishNotification {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PublishMessage for PublishNotification {
    fn root(&self) -> &Root {
        &self.root
    }

    fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }
}

impl PublishNotification {
    /// Create a new PublishNotification signed by the IdP.
    pub fn new(
        root: Root,
        proof: Proof,
        sequence_number: SequenceNumber,
        keypair: &KeyPair,
    ) -> Self {
        let notification = Self {
            root,
            proof,
            sequence_number,
            id: Digest::default(),
            signature: Signature::default(),
        };
        let id = notification.digest();
        let signature = Signature::new(&id, keypair);
        Self {
            id,
            signature,
            ..notification
        }
    }

    /// Verify a publish notification (very CPU-intensive).
    pub async fn verify(&self, committee: &Committee, previous_root: &Root) -> MessageResult<()> {
        // Ensure the id is well formed.
        ensure!(
            self.digest() == self.id,
            MessageError::MalformedNotificationId(self.id.clone())
        );

        // Verify the signature on the publish notification
        self.signature.verify(&self.id, &committee.idp.name)?;

        // Verify the commit proof.
        let hashes = vec![*previous_root, self.root];
        vkd::auditor::audit_verify::<Blake3>(hashes, self.proof.clone()).await?;

        Ok(())
    }
}

/// A vote for a publish notification.
#[derive(Serialize, Deserialize, Clone)]
pub struct PublishVote {
    /// The root commitment of the publish notification.
    #[serde(serialize_with = "serialize_root")]
    #[serde(deserialize_with = "deserialize_root")]
    pub root: Root,
    /// The sequence number of the publish notification.
    pub sequence_number: SequenceNumber,
    /// The witness creating the vote.
    pub author: PublicKey,
    /// A signature authenticating the vote.
    pub signature: Signature,
}

impl std::fmt::Debug for PublishVote {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.sequence_number,
            self.author,
            base64::encode(self.root.as_bytes())
        )
    }
}

// Useful for tests.
impl PartialEq for PublishVote {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.sequence_number == other.sequence_number
            && self.author == other.author
    }
}

impl PublishMessage for PublishVote {
    fn root(&self) -> &Root {
        &self.root
    }

    fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }
}

impl PublishVote {
    /// Create a new vote for a publish notification (signed by a witness).
    pub fn new(notification: &PublishNotification, keypair: &KeyPair) -> Self {
        let vote = Self {
            root: notification.root,
            sequence_number: notification.sequence_number,
            author: keypair.public(),
            signature: Signature::default(),
        };
        Self {
            signature: Signature::new(&vote.digest(), keypair),
            ..vote
        }
    }

    /// Verify that the vote is correctly signed.
    pub fn verify(&self, committee: &Committee) -> MessageResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.voting_power(&self.author) > 0,
            MessageError::UnknownWitness(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(MessageError::from)
    }
}

/// A certificate over a publish notification.
#[derive(Serialize, Deserialize, Clone)]
pub struct PublishCertificate {
    /// The root commitment of the certified notification.
    #[serde(serialize_with = "serialize_root")]
    #[serde(deserialize_with = "deserialize_root")]
    pub root: Root,
    /// The sequence number of the publish notification.
    pub sequence_number: SequenceNumber,
    /// The quorum of votes making the certificate.
    pub votes: Vec<(PublicKey, Signature)>,
}

impl std::fmt::Debug for PublishCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}: C{}({})",
            self.digest(),
            self.sequence_number,
            base64::encode(self.root.as_bytes())
        )
    }
}

impl std::fmt::Display for PublishCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "C{}", self.sequence_number,)
    }
}

// Useful for tests.
impl PartialEq for PublishCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.sequence_number == other.sequence_number
    }
}

impl PublishMessage for PublishCertificate {
    fn root(&self) -> &Root {
        &self.root
    }

    fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }
}

impl PublishCertificate {
    /// Verify that certificate.
    pub fn verify(&self, committee: &Committee) -> MessageResult<()> {
        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), MessageError::WitnessReuse(*name));
            let voting_power = committee.voting_power(name);
            ensure!(voting_power > 0, MessageError::UnknownWitness(*name));
            used.insert(*name);
            weight += voting_power;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            MessageError::CertificateRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(MessageError::from)
    }
}
