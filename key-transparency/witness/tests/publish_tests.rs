use vkd::{
    directory::Directory,
    ecvrf::HardCodedAkdVRF,
    storage::{
        memory::AsyncInMemoryDatabase,
        types::{AkdLabel, AkdValue},
    },
};
use function_name::named;
use futures::future::try_join_all;
use messages::{
    error::WitnessError,
    publish::{PublishCertificate, PublishNotification, PublishVote},
    sync::State,
    Blake3, WitnessToIdPMessage,
};
use test_utils::{
    broadcast_certificate, broadcast_notification, certificate, committee, delete_storage, keys,
    notification, proof, spawn_test_witnesses, votes,
};

#[tokio::test]
#[named]
async fn correct_notification() {
    let base_port = 7_000;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Broadcast a publish notification.
    let notification = notification().await;
    let handles = broadcast_notification(notification, &committee).await;

    // Wait for the witnesses' replies.
    let mut replies: Vec<_> = try_join_all(handles)
        .await
        .unwrap()
        .iter()
        .map(|reply| match bincode::deserialize(&reply).unwrap() {
            WitnessToIdPMessage::PublishVote(Ok(vote)) => vote,
            _ => panic!("Unexpected protocol message"),
        })
        .collect();
    replies.sort_by_key(|x| x.author);

    // Ensure the received votes are as expected.
    let mut expected_votes = votes().await;
    expected_votes.sort_by_key(|x| x.author);
    assert_eq!(replies, expected_votes);

    // Delete the storage.
    delete_storage(&test_id);
}

#[tokio::test]
#[named]
async fn unexpected_sequence_number() {
    let base_port = 7_100;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Make a publish notification with a bad sequence number.
    let bad_sequence_number = 2;
    let (_, identity_provider) = keys().pop().unwrap();
    let (_, root, proof) = proof().await;
    let notification = PublishNotification::new(
        root,
        proof,
        /* sequence_number */ bad_sequence_number,
        /* keypair */ &identity_provider,
    );

    // Broadcast the notification.
    let handles = broadcast_notification(notification, &committee).await;

    // Ensure the witnesses' replies are as expected.
    for reply in try_join_all(handles).await.unwrap() {
        match bincode::deserialize(&reply).unwrap() {
            WitnessToIdPMessage::PublishVote(Err(WitnessError::UnexpectedSequenceNumber {
                expected,
                got,
            })) => {
                assert_eq!(expected, 1);
                assert_eq!(got, bad_sequence_number);
            }
            _ => panic!("Unexpected protocol message"),
        }
    }

    // Delete the storage.
    delete_storage(&test_id);
}

#[tokio::test]
#[named]
async fn conflicting_notification() {
    let base_port = 7_200;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Broadcast a first notification.
    let notification = notification().await;
    let notification_root = notification.root.clone();
    let handles = broadcast_notification(notification, &committee).await;
    let _ = try_join_all(handles).await.unwrap();

    // Make a conflicting proof of update.
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let vkd = Directory::new::<Blake3>(&db, &vrf, false).await.unwrap();
    vkd.publish::<Blake3>(vec![(AkdLabel(vec![1, 2, 3]), AkdValue(vec![3, 4, 6]))])
        .await
        .unwrap();
    let current_azks = vkd.retrieve_current_azks().await.unwrap();
    let root = vkd
        .get_root_hash_at_epoch::<Blake3>(&current_azks, /* sequence number */ 1)
        .await
        .unwrap();

    // Generate the audit proof.
    let proof = vkd.audit::<Blake3>(0, 1).await.unwrap();

    // Broadcast a conflicting notification.
    let (_, identity_provider) = keys().pop().unwrap();
    let conflict = PublishNotification::new(
        root,
        proof,
        /* sequence number */ 1,
        /* keypair */ &identity_provider,
    );
    let conflict_root = conflict.root.clone();
    let handles = broadcast_notification(conflict, &committee).await;

    // Ensure the witnesses' replies are as expected.
    for reply in try_join_all(handles).await.unwrap() {
        match bincode::deserialize(&reply).unwrap() {
            WitnessToIdPMessage::PublishVote(Err(WitnessError::ConflictingNotification {
                lock,
                received,
            })) => {
                assert_eq!(lock, notification_root);
                assert_eq!(received, conflict_root);
            }
            _ => panic!("Unexpected protocol message"),
        }
    }

    // Delete the storage.
    delete_storage(&test_id);
}

#[tokio::test]
#[named]
async fn expected_certificate() {
    let base_port = 7_300;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Broadcast a certificate.
    let certificate = certificate().await;
    let handles = broadcast_certificate(certificate, &committee).await;

    // Make the expected state.
    let (_, root, _) = proof().await;
    let expected = State {
        root,
        sequence_number: 2,
        lock: None,
    };
    println!("{:?}", expected);

    // Ensure the witnesses' replies are as expected.
    for reply in try_join_all(handles).await.unwrap() {
        match bincode::deserialize(&reply).unwrap() {
            WitnessToIdPMessage::State(Ok(state)) => assert_eq!(state, expected),
            _ => panic!("Unexpected protocol message"),
        }
    }

    // Delete the storage.
    delete_storage(&test_id);
}

#[tokio::test]
#[named]
async fn unexpected_certificate() {
    let base_port = 7_400;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Make a publish certificate for a future sequence number.
    let future_sequence_number = 2;
    let (_, identity_provider) = keys().pop().unwrap();
    let (_, root, proof) = proof().await;
    let notification = PublishNotification::new(
        root,
        proof,
        /* sequence_number */ future_sequence_number,
        /* keypair */ &identity_provider,
    );

    let votes: Vec<_> = keys()
        .iter()
        .map(|(_, keypair)| PublishVote::new(&notification, keypair))
        .collect();

    let certificate = PublishCertificate {
        root: notification.root.clone(),
        sequence_number: notification.sequence_number,
        votes: votes.into_iter().map(|x| (x.author, x.signature)).collect(),
    };

    // Broadcast the certificate.
    let handles = broadcast_certificate(certificate, &committee).await;

    // Ensure the witnesses' replies are as expected.
    for reply in try_join_all(handles).await.unwrap() {
        match bincode::deserialize(&reply).unwrap() {
            WitnessToIdPMessage::State(Err(WitnessError::MissingEarlierCertificates(seq))) => {
                assert_eq!(seq, 1);
            }
            _ => panic!("Unexpected protocol message"),
        }
    }

    // Delete the storage.
    delete_storage(&test_id);
}
