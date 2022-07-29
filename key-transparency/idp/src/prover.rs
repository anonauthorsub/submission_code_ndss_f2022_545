use crate::STORE_LAST_NOTIFICATION_ADDR;
use vkd::{directory::Directory, ecvrf::HardCodedAkdVRF};
use crypto::KeyPair;
use futures::executor::block_on;
use messages::{
    publish::{Proof, PublishNotification},
    update::Batch,
    Blake3, Root, SequenceNumber,
};
use storage::Storage;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

/// Create publish notifications from client requests.
pub struct Prover<AkdStorage> {
    /// The private key material of the IdP.
    keypair: KeyPair,
    /// Receive batches of clients' requests.
    rx_batch: Receiver<Batch>,
    /// Outputs handles waiting to receive witnesses' votes.
    tx_notification: Sender<PublishNotification>,
    /// The sequence number of the last notification created by the IdP.
    sequence_number: SequenceNumber,
    /// The `vkd` key directory.
    vkd: Directory<AkdStorage, HardCodedAkdVRF>,
}

impl<AkdStorage> Prover<AkdStorage>
where
    AkdStorage: vkd::storage::Storage + Sync + Send + 'static,
{
    /// Spawn a new `Prover`.
    pub fn spawn(
        keypair: KeyPair,
        secure_storage: &Storage,
        vkd_storage: AkdStorage,
        rx_batch: Receiver<Batch>,
        tx_notification: Sender<PublishNotification>,
    ) -> JoinHandle<()> {
        // Load the last sequence number and perform initialization steps.
        let sequence_number = block_on(Self::initialize(secure_storage, &tx_notification));

        // Run the prover in a new task.
        tokio::spawn(async move {
            // Make or load the vkd directory.
            let db = vkd_storage;
            let vrf = HardCodedAkdVRF {};
            let vkd = Directory::new::<Blake3>(&db, &vrf, false)
                .await
                .expect("Failed to create vkd");

            // Run a new `NotificationMaker`.
            Self {
                keypair,
                rx_batch,
                tx_notification,
                sequence_number,
                vkd,
            }
            .run()
            .await;
        })
    }

    /// Load the last sequence number from storage and perform initialization steps.
    async fn initialize(
        storage: &Storage,
        tx_notification: &Sender<PublishNotification>,
    ) -> SequenceNumber {
        match storage
            .read(&STORE_LAST_NOTIFICATION_ADDR)
            .expect("Failed to load last notification from storage")
        {
            Some(serialized) => {
                // Deserialize the notification and extract its sequence number.
                let notification: PublishNotification =
                    bincode::deserialize(&serialized).expect("Failed to deserialize notification");
                let sequence_number = notification.sequence_number;

                // Try to re-broadcast it. This is useful in case the IdP crashes after updating its
                // last notification but before successfully broadcasting it. Otherwise it will have
                // no effect (witnesses are idempotent).
                tx_notification
                    .send(notification)
                    .await
                    .expect("Failed to deliver serialized notification");

                sequence_number
            }
            None => SequenceNumber::default(),
        }
    }

    /// Compute an audit proof from a batch of requests.
    async fn make_proof(&mut self, batch: Batch) -> (Root, Proof) {
        let current = self.sequence_number;
        let next = current + 1;

        // Persist the batch.
        self.vkd
            .publish::<Blake3>(batch)
            .await
            .expect("Failed to persist publish request");

        // Extract the latest root.
        let current_azks = self.vkd.retrieve_current_azks().await.unwrap();
        let root = self
            .vkd
            .get_root_hash_at_epoch::<Blake3>(&current_azks, next)
            .await
            .unwrap();

        // Generate the audit proof.
        let proof = self
            .vkd
            .audit::<Blake3>(current, next)
            .await
            .expect("Failed to create audit proof");

        // Output the latest root hash and the audit proof.
        (root, proof)
    }

    /// Main loop receiving batches of client requests.
    async fn run(&mut self) {
        while let Some(batch) = self.rx_batch.recv().await {
            #[cfg(feature = "benchmark")]
            Self::link_requests_and_notifications(self.sequence_number + 1, &batch);

            // Compute the audit proof (CPU-intensive).
            let (root, proof) = self.make_proof(batch).await;

            // Increment the sequence number.
            self.sequence_number += 1;

            // Make a new publish notification.
            let notification =
                PublishNotification::new(root, proof, self.sequence_number, &self.keypair);

            // Send the notification to the broadcaster.
            self.tx_notification
                .send(notification)
                .await
                .expect("Failed to deliver serialized notification");
        }
    }

    #[cfg(feature = "benchmark")]
    fn link_requests_and_notifications(sequence: SequenceNumber, batch: &Batch) {
        for request in batch {
            let (label, _) = request;
            let id = u64::from_be_bytes(label.0[0..8].try_into().unwrap());
            log::info!("Batch {} contains sample tx {}", sequence, id);
        }
    }
}
