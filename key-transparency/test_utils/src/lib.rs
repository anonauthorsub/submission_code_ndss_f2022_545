use vkd::{
    directory::Directory, ecvrf::HardCodedAkdVRF, storage::memory::AsyncInMemoryDatabase, AkdLabel,
    AkdValue,
};
use bytes::Bytes;
use config::{Committee, Idp, Witness};
use crypto::{KeyPair, PublicKey};
use futures::{stream::StreamExt, SinkExt};
use idp::spawn_idp;
use messages::{
    publish::{Proof, PublishCertificate, PublishNotification, PublishVote},
    update::UpdateRequest,
    Blake3, IdPToWitnessMessage, Root, WitnessToIdPMessage,
};
use network::reliable_sender::{CancelHandler, ReliableSender};
use rand::{rngs::StdRng, SeedableRng};
use std::net::SocketAddr;
use storage::Storage;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use witness::spawn_witness;

// Test cryptographic keys.
pub fn keys() -> Vec<(PublicKey, KeyPair)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| KeyPair::generate_keypair(&mut rng))
        .collect()
}

// Test committee.
pub fn committee(base_port: u16) -> Committee {
    Committee {
        idp: Idp {
            name: keys().pop().unwrap().0,
            address: format!("127.0.0.1:{}", base_port).parse().unwrap(),
        },
        witnesses: keys()
            .into_iter()
            .enumerate()
            .map(|(i, (name, _))| {
                (
                    name,
                    Witness {
                        voting_power: 1,
                        address: format!("127.0.0.1:{}", base_port + 1 + i as u16)
                            .parse()
                            .unwrap(),
                    },
                )
            })
            .collect(),
    }
}

// Test update requests.
pub fn updates() -> Vec<UpdateRequest> {
    (0..2)
        .map(|i| {
            let label = AkdLabel(vec![1, i]);
            let value = AkdValue(vec![2, i]);
            (label, value)
        })
        .collect()
}

// Serialized test update requests.
pub fn serialized_updates() -> Vec<Bytes> {
    updates()
        .iter()
        .map(|update| Bytes::from(bincode::serialize(&update).unwrap()))
        .collect()
}

// Test proof and root hashes.
pub async fn proof() -> (Root, Root, Proof) {
    // Get test key values.
    let items = updates();

    // Create a test tree with dumb key-values.
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let vkd = Directory::new::<Blake3>(&db, &vrf, false).await.unwrap();

    // Compute the start root (at sequence 0) and end root (at sequence 1).
    let current_azks = vkd.retrieve_current_azks().await.unwrap();
    let start_root = vkd
        .get_root_hash_at_epoch::<Blake3>(&current_azks, /* sequence number */ 0)
        .await
        .unwrap();

    vkd.publish::<Blake3>(items).await.unwrap();

    let current_azks = vkd.retrieve_current_azks().await.unwrap();
    let end_root = vkd
        .get_root_hash_at_epoch::<Blake3>(&current_azks, /* sequence number */ 1)
        .await
        .unwrap();

    // Generate the audit proof.
    let proof = vkd.audit::<Blake3>(0, 1).await.unwrap();

    // Return the start root, end root, and the audit proof.
    (start_root, end_root, proof)
}

// Test publish notification.
pub async fn notification() -> PublishNotification {
    let (_, identity_provider) = keys().pop().unwrap();
    let (_, root, proof) = proof().await;
    PublishNotification::new(
        root,
        proof,
        /* sequence_number */ 1,
        /* keypair */ &identity_provider,
    )
}

// The witnesses' votes over a test notification.
pub async fn votes() -> Vec<PublishVote> {
    let notification = notification().await;
    keys()
        .iter()
        .map(|(_, keypair)| PublishVote::new(&notification, keypair))
        .collect()
}

// A test certificate.
pub async fn certificate() -> PublishCertificate {
    let notification = notification().await;
    PublishCertificate {
        root: notification.root,
        sequence_number: notification.sequence_number,
        votes: votes()
            .await
            .into_iter()
            .map(|x| (x.author, x.signature))
            .collect(),
    }
}

// Spawn test witnesses.
pub fn spawn_test_witnesses(test_id: &str, committee: &Committee) {
    delete_storage(test_id);
    for (i, (_, keypair)) in keys().into_iter().enumerate() {
        let secure_storage_path = format!(".test_secure_storage_{}_{}", test_id, i);
        let secure_storage = Storage::new(&secure_storage_path).unwrap();

        let audit_storage_path = format!(".test_audit_storage_{}_{}", test_id, i);
        let audit_storage = Storage::new(&audit_storage_path).unwrap();

        spawn_witness(keypair, committee.clone(), secure_storage, audit_storage);
    }
}

// Spawn test idp.
pub fn spawn_test_idp(test_id: &str, committee: Committee) {
    delete_storage(test_id);
    let (_, keypair) = keys().pop().unwrap();

    let secure_storage_path = format!(".test_idp_secure_storage_{}", test_id);
    let secure_storage = Storage::new(&secure_storage_path).unwrap();

    let sync_storage_path = format!(".test_sync_storage_{}", test_id);
    let sync_storage = Storage::new(&sync_storage_path).unwrap();

    let batch_size = serialized_updates().len();
    let max_batch_delay = 200;

    tokio::spawn(async move {
        spawn_idp(
            keypair,
            committee.clone(),
            secure_storage,
            sync_storage,
            /* vkd_storage */ AsyncInMemoryDatabase::new(),
            batch_size,
            max_batch_delay,
        )
        .await;
    });
}

// Helper function deleting a test storage.
pub fn delete_storage(test_id: &str) {
    for i in 0..keys().len() {
        let secure_storage_path = format!(".test_secure_storage_{}_{}", test_id, i);
        let _ = std::fs::remove_dir_all(&secure_storage_path);
        let audit_storage_path = format!(".test_audit_storage_{}_{}", test_id, i);
        let _ = std::fs::remove_dir_all(&audit_storage_path);
    }
    let idp_secure_storage_path = format!(".test_idp_secure_storage_{}", test_id);
    let _ = std::fs::remove_dir_all(&idp_secure_storage_path);
    let sync_storage_path = format!(".test_sync_storage_{}", test_id);
    let _ = std::fs::remove_dir_all(&sync_storage_path);
}

// Broadcast a publish notification to the witnesses.
pub async fn broadcast_notification(
    notification: PublishNotification,
    committee: &Committee,
) -> Vec<CancelHandler> {
    let addresses = committee
        .witnesses_addresses()
        .into_iter()
        .map(|(_, address)| address)
        .collect();
    let message = IdPToWitnessMessage::PublishNotification(notification);
    let serialized = bincode::serialize(&message).unwrap();
    let bytes = Bytes::from(serialized);
    let mut sender = ReliableSender::new();
    sender.broadcast(addresses, bytes).await
}

// Broadcast a publish certificate to the witnesses.
pub async fn broadcast_certificate(
    certificate: PublishCertificate,
    committee: &Committee,
) -> Vec<CancelHandler> {
    let addresses = committee
        .witnesses_addresses()
        .into_iter()
        .map(|(_, address)| address)
        .collect();
    let message = IdPToWitnessMessage::PublishCertificate(certificate);
    let serialized = bincode::serialize(&message).unwrap();
    let bytes = Bytes::from(serialized);
    let mut sender = ReliableSender::new();
    sender.broadcast(addresses, bytes).await
}

// A test network listener emulating a witness. It replies to a publish notification
// with a vote and then listen to a publish certificate.
pub fn listener(
    address: SocketAddr,
    keypair: KeyPair,
) -> JoinHandle<(PublishNotification, PublishCertificate)> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let mut transport = Framed::new(socket, LengthDelimitedCodec::new());

        // Wait for a publish notification and reply with a vote.
        let notification = match transport.next().await {
            Some(Ok(bytes)) => match bincode::deserialize(&bytes).unwrap() {
                IdPToWitnessMessage::PublishNotification(n) => {
                    let vote = PublishVote::new(&n, &keypair);
                    let message = WitnessToIdPMessage::PublishVote(Ok(vote));
                    let serialized = bincode::serialize(&message).unwrap();
                    transport.send(Bytes::from(serialized)).await.unwrap();
                    n
                }
                _ => panic!("Unexpected protocol message"),
            },
            _ => panic!("Failed to receive network message"),
        };

        // Wait for a publish certificate.
        let certificate = match transport.next().await {
            Some(Ok(bytes)) => match bincode::deserialize(&bytes).unwrap() {
                IdPToWitnessMessage::PublishCertificate(c) => c,
                _ => panic!("Unexpected protocol message"),
            },
            _ => panic!("Failed to receive network message"),
        };

        // Output both the notification and certificate.
        (notification, certificate)
    })
}
