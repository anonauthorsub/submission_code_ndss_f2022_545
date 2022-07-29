mod aggregator;
mod batcher;
mod prover;
mod publisher;
mod synchronizer;

use async_trait::async_trait;
use batcher::Batcher;
use bytes::Bytes;
use config::Committee;
use crypto::KeyPair;
use futures::{future::join_all, SinkExt};
use log::info;
use network::receiver::{MessageHandler, Receiver as NetworkReceiver, Writer};
use prover::Prover;
use publisher::Publisher;
use std::error::Error;
use storage::Storage;
use synchronizer::Synchronizer;
use tokio::sync::mpsc::{channel, Sender};

/// Storage address of the sequence number.
pub(crate) const STORE_LAST_NOTIFICATION_ADDR: [u8; 32] = [255; 32];

/// The default size of inter-tasks channels.
pub(crate) const DEFAULT_CHANNEL_SIZE: usize = 1_000;

/// Spawn a new IdP.
pub async fn spawn_idp<AkdStorage>(
    // The keypair of the IdP.
    keypair: KeyPair,
    // The committee information.
    committee: Committee,
    // The secure storage containing the last publish notification.
    secure_storage: Storage,
    // The storage containing all past certificates.
    sync_storage: Storage,
    // The big storage containing all key-values.
    vkd_storage: AkdStorage,
    // The number of updates to batch into a single proof.
    batch_size: usize,
    // The maximum delay before sealing a batch of requests.
    max_batch_delay: u64,
) where
    AkdStorage: vkd::storage::Storage + Sync + Send + 'static,
{
    let (tx_request, rx_request) = channel(DEFAULT_CHANNEL_SIZE);
    let (tx_batch, rx_batch) = channel(DEFAULT_CHANNEL_SIZE);
    let (tx_notification, rx_notification) = channel(DEFAULT_CHANNEL_SIZE);
    let (tx_trigger, rx_trigger) = channel(DEFAULT_CHANNEL_SIZE);
    let (tx_certificate, rx_certificate) = channel(DEFAULT_CHANNEL_SIZE);

    // The `Batcher` receives clients update requests and batch them together.
    let batcher_handle = Batcher::spawn(batch_size, max_batch_delay, rx_request, tx_batch);

    // The `Prover` persists batches of updates and generate a commit (audit) proof.
    let prover_handle = Prover::spawn(
        keypair,
        &secure_storage,
        vkd_storage,
        rx_batch,
        tx_notification,
    );

    // The `Publisher` broadcasts publish notifications to the witnesses.
    let publisher_handle = Publisher::spawn(
        committee.clone(),
        secure_storage,
        rx_notification,
        tx_trigger,
        tx_certificate,
    );

    // The `Synchronizer` helps the witnesses to remain up to date.
    let synchronizer_handle =
        Synchronizer::spawn(committee.clone(), sync_storage, rx_trigger, rx_certificate);

    // Spawn a network receiver.
    let name = committee.idp.name;
    let mut address = committee.idp.address;
    address.set_ip("0.0.0.0".parse().unwrap());
    let handler = IdpHandler { tx_request };
    NetworkReceiver::spawn(address, handler);

    // Prevent the function from returning.
    info!(
        "Idp {} successfully booted on {}",
        name,
        committee.idp.address.ip()
    );
    join_all(vec![
        batcher_handle,
        prover_handle,
        publisher_handle,
        synchronizer_handle,
    ])
    .await;
}

/// Defines how the network receiver handles incoming messages.
#[derive(Clone)]
struct IdpHandler {
    tx_request: Sender<Bytes>,
}

#[async_trait]
impl MessageHandler for IdpHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Reply with an ACK.
        let _ = writer.send(Bytes::from("Ack")).await;

        // Forward the request to the `Batcher`.
        self.tx_request
            .send(serialized)
            .await
            .expect("Failed to deliver request");
        Ok(())
    }
}
