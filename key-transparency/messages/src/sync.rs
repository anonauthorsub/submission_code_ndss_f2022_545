use crate::{
    deserialize_root,
    publish::{PublishMessage, PublishVote},
    serialize_root, Blake3, Root, SequenceNumber,
};
use vkd::{directory::Directory, ecvrf::HardCodedAkdVRF, storage::memory::AsyncInMemoryDatabase};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};

/// The safety-critical state of a witness.
#[derive(Serialize, Deserialize, Clone)]
pub struct State {
    /// The latest root commitment.
    #[serde(serialize_with = "serialize_root")]
    #[serde(deserialize_with = "deserialize_root")]
    pub root: Root,
    /// The current sequence number.
    pub sequence_number: SequenceNumber,
    /// The notification on which this entity is locked.
    pub lock: Option<PublishVote>,
}

impl Default for State {
    fn default() -> Self {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let vkd = block_on(Directory::new::<Blake3>(&db, &vrf, false))
            .expect("Failed to create empty tree directory");
        let current_azks = block_on(vkd.retrieve_current_azks()).expect("Failed to compute azks");
        let root = block_on(vkd.get_root_hash_at_epoch::<Blake3>(&current_azks, 0))
            .expect("Failed to compute initial root hash");

        Self {
            root,
            sequence_number: 1,
            lock: None,
        }
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "State{}({:?}, {:?})",
            self.sequence_number,
            self.root,
            self.lock.as_ref().map(|vote| vote.digest())
        )
    }
}

// Useful for tests.
impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.sequence_number == other.sequence_number
            && self.lock == other.lock
    }
}

/// Request of a publish certificate request.
#[derive(Serialize, Deserialize)]
pub struct PublishCertificateQuery {
    /// The sequence number of the requested certificate.
    pub sequence_number: SequenceNumber,
}

impl std::fmt::Debug for PublishCertificateQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "CertRequest({})", self.sequence_number)
    }
}
