use crate::Replier;
use config::Committee;
use crypto::KeyPair;
use log::{debug, info, warn};
use messages::{
    ensure,
    error::{WitnessError, WitnessResult},
    publish::{PublishCertificate, PublishMessage, PublishNotification, PublishVote},
    sync::State,
    SequenceNumber, SerializedPublishCertificateMessage, WitnessToIdPMessage,
};
use storage::Storage;
use tokio::sync::mpsc::{Receiver, Sender};

/// Storage address of the state.
pub const STORE_STATE_ADDR: [u8; 32] = [255; 32];

/// Core logic handing publish notifications and certificates.
pub struct PublishHandler {
    /// The keypair of this authority.
    keypair: KeyPair,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    storage: Storage,
    /// Receive publish notifications from the IdP.
    rx_notification: Receiver<(PublishNotification, Replier)>,
    /// Receive publish certificates from the IdP.
    rx_certificate: Receiver<(
        SerializedPublishCertificateMessage,
        PublishCertificate,
        Replier,
    )>,
    /// Receive state queries from the IdP.
    rx_state_query: Receiver<Replier>,
    /// Outputs processed (thus verified) publish certificates.
    tx_processed_certificate: Sender<(SerializedPublishCertificateMessage, SequenceNumber)>,
    /// The state of the witness.
    state: State,
}

impl PublishHandler {
    /// Spawn a new publish handler task.
    pub fn spawn(
        keypair: KeyPair,
        committee: Committee,
        storage: Storage,
        rx_notification: Receiver<(PublishNotification, Replier)>,
        rx_certificate: Receiver<(
            SerializedPublishCertificateMessage,
            PublishCertificate,
            Replier,
        )>,
        rx_state_query: Receiver<Replier>,
        tx_processed_certificate: Sender<(SerializedPublishCertificateMessage, SequenceNumber)>,
    ) {
        tokio::spawn(async move {
            // Try to load the state from storage.
            let state = storage
                .read(&STORE_STATE_ADDR)
                .expect("Failed to load state from storage")
                .map(|bytes| bincode::deserialize(&bytes).expect("Failed to deserialize state"))
                .unwrap_or_default();

            // Run an instance of the handler.
            Self {
                keypair,
                committee,
                storage,
                rx_notification,
                rx_certificate,
                rx_state_query,
                tx_processed_certificate,
                state,
            }
            .run()
            .await
        });
    }

    /// Try to vote for a publish notification.
    async fn make_vote(&self, notification: &PublishNotification) -> WitnessResult<PublishVote> {
        // Verify the notification.
        notification
            .verify(&self.committee, &self.state.root)
            .await?;

        // Check the sequence number.
        ensure!(
            self.state.sequence_number == notification.sequence_number(),
            WitnessError::UnexpectedSequenceNumber {
                expected: self.state.sequence_number,
                got: notification.sequence_number()
            }
        );

        // Ensure there are no locks.
        match self.state.lock.as_ref() {
            Some(vote) => {
                ensure!(
                    vote.root() == notification.root(),
                    WitnessError::ConflictingNotification {
                        lock: *vote.root(),
                        received: *notification.root()
                    }
                );
                Ok(vote.clone())
            }
            None => Ok(PublishVote::new(notification, &self.keypair)),
        }
    }

    /// Process a publish certificate.
    fn process_certificate(&self, certificate: &PublishCertificate) -> WitnessResult<()> {
        // Verify the certificate's validity.
        certificate.verify(&self.committee)?;

        // Ensure the witness is not missing previous certificates.
        ensure!(
            self.state.sequence_number >= certificate.sequence_number(),
            WitnessError::MissingEarlierCertificates(self.state.sequence_number)
        );
        Ok(())
    }

    /// Main loop listening to verified IdP's notification messages.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                // Receive publish notifications.
                Some((notification, replier)) = self.rx_notification.recv() => {
                    debug!("Received {:?}", notification);
                    let reply = match self.make_vote(&notification).await {
                        Err(e) => {
                            warn!("{}", e);

                            // Reply with an error message.
                            WitnessToIdPMessage::PublishVote(Err(e))
                        },
                        Ok(vote) => {
                            debug!("Create {:?}", vote);

                            // Register the lock.
                            self.state.lock = Some(vote.clone());
                            let serialized_state = bincode::serialize(&self.state)
                                .expect("Failed to serialize state");
                            self.storage.write(&STORE_STATE_ADDR, &serialized_state)
                                .expect("Failed to persist state");

                            // Reply with a vote.
                            WitnessToIdPMessage::PublishVote(Ok(vote))
                        }
                    };
                    replier.send(reply).expect("Failed to reply to notification");
                },

                // Receive publish certificates.
                Some((serialized, certificate, replier)) = self.rx_certificate.recv() => {
                    debug!("Received {:?}", certificate);
                    let reply = match self.process_certificate(&certificate) {
                        Err(e) => {
                            warn!("{}", e);

                            // Reply with an error message.
                            WitnessToIdPMessage::State(Err(e))
                        },
                        Ok(()) => {
                            if self.state.sequence_number == certificate.sequence_number() {
                                // Update the witness state.
                                #[cfg(not(feature = "witness-only-benchmark"))]
                                {
                                    // Do not update the state root when running benchmarks. This allows the
                                    // benchmark client to re-use the same proof (and thus not becoming the
                                    // CPU bottleneck).
                                    self.state.root = *certificate.root();
                                }
                                self.state.sequence_number += 1;
                                self.state.lock = None;

                                let serialized_state = bincode::serialize(&self.state)
                                    .expect("Failed to serialize state");
                                self.storage.write(&STORE_STATE_ADDR, &serialized_state)
                                    .expect("Failed to persist state");

                                debug!("Commit {:?}", certificate);
                                // NOTE: These log entries are used to compute performance.
                                info!("Commit {}", certificate);

                                // Send the serialized certificate to the sync helper.
                                self
                                    .tx_processed_certificate
                                    .send((serialized, certificate.sequence_number()))
                                    .await
                                    .expect("Failed to send certificate to sync helper");
                            } else {
                                debug!("Already processed {:?}", certificate);
                            }

                            // Reply with an acknowledgement.
                            WitnessToIdPMessage::State(Ok(self.state.clone()))
                        }
                    };
                    replier.send(reply).expect("Failed to reply to certificate");
                }

                // Receive state queries.
                Some(replier) = self.rx_state_query.recv() => {
                    let reply =  WitnessToIdPMessage::State(Ok(self.state.clone()));
                    replier.send(reply).expect("Failed to reply to state query");
                }
            }
        }
    }
}
