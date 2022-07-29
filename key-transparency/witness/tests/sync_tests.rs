use bytes::Bytes;
use function_name::named;
use futures::future::try_join_all;
use messages::{
    publish::PublishCertificate,
    sync::{PublishCertificateQuery, State},
    IdPToWitnessMessage, WitnessToIdPMessage,
};
use network::reliable_sender::ReliableSender;
use test_utils::{
    broadcast_certificate, committee, delete_storage, notification, spawn_test_witnesses, votes,
};

#[tokio::test]
#[named]
async fn state_query() {
    let base_port = 8_000;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Broadcast a state query.
    let addresses = committee
        .witnesses_addresses()
        .into_iter()
        .map(|(_, address)| address)
        .collect();
    let message = IdPToWitnessMessage::StateQuery;
    let serialized = bincode::serialize(&message).unwrap();
    let bytes = Bytes::from(serialized);
    let mut sender = ReliableSender::new();
    let handles = sender.broadcast(addresses, bytes).await;

    // Make the expected state.
    let expected = State::default();

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
async fn sync_request() {
    let base_port = 8_100;
    let committee = committee(base_port);
    let test_id = function_name!();

    // Spawn 4 witnesses.
    spawn_test_witnesses(&test_id, &committee);
    tokio::task::yield_now().await;

    // Broadcast a certificate.
    let notification = notification().await;
    let certificate = PublishCertificate {
        root: notification.root,
        sequence_number: notification.sequence_number,
        votes: votes()
            .await
            .into_iter()
            .map(|x| (x.author, x.signature))
            .collect(),
    };
    let handles = broadcast_certificate(certificate.clone(), &committee).await;
    let _ = try_join_all(handles).await.unwrap();

    // Broadcast a sync request.
    let request = PublishCertificateQuery {
        sequence_number: notification.sequence_number,
    };

    let addresses = committee
        .witnesses_addresses()
        .into_iter()
        .map(|(_, address)| address)
        .collect();
    let message = IdPToWitnessMessage::PublishCertificateQuery(request);
    let serialized = bincode::serialize(&message).unwrap();
    let bytes = Bytes::from(serialized);
    let mut sender = ReliableSender::new();
    let handles = sender.broadcast(addresses, bytes).await;

    // Ensure the witnesses' replies are as expected.
    for reply in try_join_all(handles).await.unwrap() {
        match bincode::deserialize(&reply).unwrap() {
            WitnessToIdPMessage::PublishCertificateResponse(received) => {
                match bincode::deserialize(&received).unwrap() {
                    IdPToWitnessMessage::PublishCertificate(cert) => {
                        assert_eq!(cert, certificate);
                    }
                    _ => panic!("Unexpected response"),
                }
            }
            _ => panic!("Unexpected protocol message"),
        }
    }

    // Delete the storage.
    delete_storage(&test_id);
}
