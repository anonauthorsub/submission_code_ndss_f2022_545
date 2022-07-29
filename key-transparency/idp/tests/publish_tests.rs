use function_name::named;
use futures::future::try_join_all;
use network::reliable_sender::ReliableSender;
use test_utils::{
    certificate, committee, delete_storage, keys, listener, notification, proof,
    serialized_updates, spawn_test_idp,
};

#[tokio::test]
#[named]
async fn correct_update() {
    let base_port = 9_000;
    let committee = committee(base_port);
    let address = committee.idp.address;
    let test_id = function_name!();

    // Spawn the IdP.
    spawn_test_idp(&test_id, committee.clone());
    tokio::task::yield_now().await;

    // Spawn the listeners acting as witnesses.
    let received: Vec<_> = keys()
        .into_iter()
        .map(|(name, key)| {
            let address = committee.witness_address(&name).unwrap();
            listener(address, key)
        })
        .collect();

    // Send a enough correct updates to create a batch.
    let mut network = ReliableSender::new();
    for update in serialized_updates() {
        let handle = network.send(address, update).await;
        handle.await.unwrap();
    }

    // Ensure the listener received the expected messages.
    let (start_root, _, _) = proof().await;
    let expected_notification = notification().await;
    let expected_certificate = certificate().await;
    for (notification, certificate) in try_join_all(received).await.unwrap() {
        assert!(notification.verify(&committee, &start_root).await.is_ok());
        assert_eq!(notification, expected_notification);
        assert!(certificate.verify(&committee).is_ok());
        assert_eq!(certificate, expected_certificate);
    }

    // Delete the storage.
    delete_storage(&test_id);
}

#[tokio::test]
#[named]
async fn faulty_witness() {
    let base_port = 9_100;
    let committee = committee(base_port);
    let address = committee.idp.address;
    let test_id = function_name!();

    // Spawn the IdP.
    spawn_test_idp(&test_id, committee.clone());
    tokio::task::yield_now().await;

    // Spawn the listeners acting as witnesses.
    let received: Vec<_> = keys()
        .into_iter()
        .skip(1)
        .map(|(name, key)| {
            let address = committee.witness_address(&name).unwrap();
            listener(address, key)
        })
        .collect();

    // Send enough correct updates to create a batch.
    let mut network = ReliableSender::new();
    for update in serialized_updates() {
        let handle = network.send(address, update).await;
        handle.await.unwrap();
    }

    // Ensure the listener received the expected messages.
    let (start_root, _, _) = proof().await;
    let expected_notification = notification().await;
    let expected_certificate = certificate().await;
    for (notification, certificate) in try_join_all(received).await.unwrap() {
        assert!(notification.verify(&committee, &start_root).await.is_ok());
        assert_eq!(notification, expected_notification);
        assert!(certificate.verify(&committee).is_ok());
        assert_eq!(certificate, expected_certificate);
    }

    // Delete the storage.
    delete_storage(&test_id);
}
