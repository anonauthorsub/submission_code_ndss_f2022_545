use bytes::Bytes;
use config::Committee;
use crypto::PublicKey;
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use log::debug;
use messages::SequenceNumber;
use network::reliable_sender::{CancelHandler, ReliableSender};
use std::collections::HashMap;
use storage::Storage;
use tokio::{
    sync::{mpsc::Receiver, oneshot},
    task::JoinHandle,
};

/// The maximum number of pending updates per witness.
const MAX_PENDING_UPDATES: usize = 100;

/// Signal to the synchronizer to update a specific witness.
#[derive(Debug)]
pub struct SyncTrigger {
    /// The witness to update.
    pub target: PublicKey,
    /// The current sequence number of that witness.
    pub sequence_number: SequenceNumber,
    /// An optional message to resent after the witness is updated.
    pub retry: Option<(Bytes, oneshot::Sender<Bytes>)>,
}

/// Notifies the synchronizer of a newly created IdP's certificate.
#[derive(Debug)]
pub struct NewCertificate {
    /// The sequence number of the new certificate.
    pub sequence_number: SequenceNumber,
    /// The serialized publish certificate message.
    pub certificate: Vec<u8>,
    /// A channel to confirm that this new certificate is correctly processed.
    pub ack: oneshot::Sender<()>,
}

/// Updates witness by providing publish certificates.
pub struct Synchronizer {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    storage: Storage,
    /// Receive signals to update a witness.
    rx_trigger: Receiver<SyncTrigger>,
    /// Receive newly created IdP's certificates.
    rx_certificate: Receiver<NewCertificate>,
    /// Holds the sequence number of the IdP.
    sequence_number: SequenceNumber,
    /// A reliable network sender.
    network: ReliableSender,
    /// Keep track of the progress of witnesses' updates. It ensures the IdP runs in
    /// finite memory (no bad witness can exhaust the IdP's resources).
    updates_in_progress: HashMap<PublicKey, usize>,
}

impl Synchronizer {
    /// Spawn a new `Synchronizer` task.
    pub fn spawn(
        committee: Committee,
        storage: Storage,
        rx_trigger: Receiver<SyncTrigger>,
        rx_certificate: Receiver<NewCertificate>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            Self {
                committee,
                storage,
                rx_trigger,
                rx_certificate,
                // It is ok to initialize the sequence number to zero. In the worst case, the IdP
                // will need a bit before becoming able to update the witnesses.
                sequence_number: SequenceNumber::default(),
                network: ReliableSender::new(),
                updates_in_progress: HashMap::new(),
            }
            .run()
            .await;
        })
    }

    /// Updates a specific witness with any certificate it may have missed.
    async fn update(
        &mut self,
        target: PublicKey,
        witness_sequence_number: SequenceNumber,
    ) -> Vec<CancelHandler> {
        debug!("Updating {}", target);
        let address = self
            .committee
            .witness_address(&target)
            .unwrap_or_else(|| panic!("Tried to update unknown witness {}", target));

        // Try to send all missing certificates to the witness.
        let mut handles = Vec::new();
        for s in witness_sequence_number..=self.sequence_number {
            // Ensure we didn't already reached the maximum pending updates for this witness.
            if let Some(counter) = self.updates_in_progress.get_mut(&target) {
                if *counter >= MAX_PENDING_UPDATES {
                    break;
                } else {
                    *counter += 1;
                }
            }

            // Load the certificate from storage and send it to the witness.
            let certificate = self
                .storage
                .read(&s.to_le_bytes())
                .expect("Failed to load certificate")
                .unwrap_or_else(|| panic!("We should have certificate {}", s));

            let bytes = Bytes::from(certificate);
            let handle = self.network.send(address, bytes).await;
            handles.push(handle);
        }
        handles
    }

    /// Helper function. It waits for a future to complete and then forwards it result through the sender.
    async fn retrial_waiter(wait_for: CancelHandler, sender: oneshot::Sender<Bytes>) {
        let bytes = wait_for
            .await
            .expect("Failed to receive response from network");
        sender
            .send(bytes)
            .expect("Failed to deliver retried message");
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn updates_waiter(wait_for: CancelHandler, name: PublicKey) -> PublicKey {
        let _ = wait_for.await;
        name
    }

    /// Main loop receiving signals to update a specific witness and newly created IdP's certificates.
    async fn run(&mut self) {
        let mut pending_updates = FuturesUnordered::new();
        let mut pending_retrials = FuturesUnordered::new();

        loop {
            tokio::select! {
                // Receives signals to update a specific witness.
                Some(trigger) = self.rx_trigger.recv() => {
                    // Update the target node.
                    let target = trigger.target;
                    let sequence_number = trigger.sequence_number;
                    let handles = self.update(target, sequence_number).await;
                    for handle in handles {
                        pending_updates.push(Self::updates_waiter(handle, target));
                    }

                    // Retry to submit the last message (if any).
                    if let Some((message, sender)) = trigger.retry {
                        let address = self
                            .committee
                            .witness_address(&target)
                            .unwrap_or_else(|| panic!("Tried to update unknown witness {}", target));
                        let handle = self.network.send(address, message).await;
                        pending_retrials.push(Self::retrial_waiter(handle, sender));
                    }
                },

                // Receives newly created IdP's certificates.
                Some(message) = self.rx_certificate.recv() => {
                    // Update the sequence number.
                    self.sequence_number = message.sequence_number;

                    // Persist the new certificate.
                    self.storage
                        .write(&self.sequence_number.to_le_bytes(), &message.certificate)
                        .expect("Failed to persist certificate");

                    // Ack that the certificate is correctly stored.
                    message.ack.send(()).expect("Failed to ack receipt of new certificate");
                },

                // Pulls the futures.
                Some(name) = pending_updates.next() => {
                    if let Some(counter) = self.updates_in_progress.get_mut(&name) {
                        *counter -= 1;
                    }
                }
                Some(()) = pending_retrials.next() => {
                    // Nothing to do.
                }
            }
        }
    }
}
