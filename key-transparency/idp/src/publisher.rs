use crate::{
    aggregator::Aggregator,
    synchronizer::{NewCertificate, SyncTrigger},
    STORE_LAST_NOTIFICATION_ADDR,
};
use bytes::Bytes;
use config::Committee;
use crypto::PublicKey;
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use log::{debug, info, warn};
use messages::{
    error::{IdpError, IdpResult, WitnessError},
    publish::{PublishNotification, PublishVote},
    IdPToWitnessMessage, Root, SequenceNumber, WitnessToIdPMessage,
};
use network::reliable_sender::{CancelHandler, ReliableSender};
use std::net::SocketAddr;
use storage::Storage;
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    task::JoinHandle,
};

/// Broadcast publish notifications to the witnesses, gather votes and broadcast certificates.
pub struct Publisher {
    /// The persistent storage.
    storage: Storage,
    /// Receive serialized publish notifications to broadcast.
    rx_notification: Receiver<PublishNotification>,
    /// Trigger the synchronizer to update the witnesses.
    tx_trigger: Sender<SyncTrigger>,
    /// Deliver newly created certificates.
    tx_certificate: Sender<NewCertificate>,
    /// A reliable network sender.
    network: ReliableSender,
    /// The public keys of the witnesses (in the same order as the `addresses` field).
    names: Vec<PublicKey>,
    /// The network addresses of the witnesses (in the same order as the `names` field).
    addresses: Vec<SocketAddr>,
    /// A votes aggregator to assemble a quorum of votes into a certificate.
    aggregator: Aggregator,
}

impl Publisher {
    /// Spawn a new broadcaster.
    pub fn spawn(
        committee: Committee,
        storage: Storage,
        rx_notification: Receiver<PublishNotification>,
        tx_trigger: Sender<SyncTrigger>,
        tx_certificate: Sender<NewCertificate>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let (names, addresses) = committee.witnesses_addresses().into_iter().unzip();
            Self {
                storage,
                rx_notification,
                tx_trigger,
                tx_certificate,
                network: ReliableSender::new(),
                names,
                addresses,
                // The aggregator will be reset with the correct root hash upon receiving the
                // first publish notification.
                aggregator: Aggregator::new(committee, Root::default()),
            }
            .run()
            .await;
        })
    }

    /// Tell the synchronizer to update a witness and then resubmit the notification.
    async fn sync_and_retry(
        &mut self,
        target: PublicKey,
        sequence_number: SequenceNumber,
        notification: Bytes,
    ) -> CancelHandler {
        let (sender, receiver) = oneshot::channel();
        let message = SyncTrigger {
            target,
            retry: Some((notification, sender)),
            sequence_number,
        };
        self.tx_trigger
            .send(message)
            .await
            .expect("Failed to deliver sync trigger");
        receiver
    }

    /// Parse the witnesses' reply to a IdP publish notification.
    fn parse_notification_reply(message: WitnessToIdPMessage) -> IdpResult<PublishVote> {
        match message {
            WitnessToIdPMessage::PublishVote(result) => result.map_err(IdpError::from),
            _ => Err(IdpError::UnexpectedProtocolMessage),
        }
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn waiter(wait_for: CancelHandler, author: PublicKey) -> (Bytes, PublicKey) {
        let reply = wait_for
            .await
            .expect("Failed to receive response from network");
        (reply, author)
    }

    /// Publish a new update to the witnesses.
    async fn publish(
        &mut self,
        notification: PublishNotification,
    ) -> Vec<(CancelHandler, PublicKey)> {
        let sequence_number = notification.sequence_number;

        // Reset the aggregator to hold the votes for ths notification.
        self.aggregator.reset(notification.root);

        // Serialize the notification.
        let message = IdPToWitnessMessage::PublishNotification(notification);
        let serialized_notification =
            bincode::serialize(&message).expect("Failed to serialize notification");

        // Persist the last notification to storage.
        self.storage
            .write(&STORE_LAST_NOTIFICATION_ADDR, &serialized_notification)
            .expect("Failed to persist notification");

        // Broadcast the publish notification to the witnesses.
        let bytes_notification = Bytes::from(serialized_notification);
        let addresses = self.addresses.clone();
        let mut wait_for_quorum: FuturesUnordered<_> = self
            .network
            .broadcast(addresses, bytes_notification.clone())
            .await
            .into_iter()
            .zip(self.names.iter().cloned())
            .map(|(handle, name)| Self::waiter(handle, name))
            .collect();

        // Collect the votes and assemble a certificate.
        while let Some((reply, author)) = wait_for_quorum.next().await {
            // Deserialize the reply.
            let message: WitnessToIdPMessage = match bincode::deserialize(&reply) {
                Ok(x) => x,
                Err(e) => {
                    warn!("{:?}", e);
                    continue;
                }
            };

            // Check if the witness is out of date. If that is the case, update it.
            if let Some(status) = message.sequence_number() {
                if status < sequence_number {
                    debug!("{} is outdated ({} < {})", author, status, sequence_number);
                    let last_notification = bytes_notification.clone();
                    let handle = self.sync_and_retry(author, status, last_notification).await;
                    wait_for_quorum.push(Self::waiter(handle, author));
                    continue;
                }
            }

            // Finally parse the publish vote.
            let vote = match Self::parse_notification_reply(message) {
                Ok(vote) => {
                    debug!("Received {:?}", vote);
                    vote
                }
                Err(e) => {
                    warn!("{:?}", e);
                    continue;
                }
            };

            // Check if we got enough votes to make a certificate.
            let potential_certificate = match self.aggregator.append(vote) {
                Ok(x) => x,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };
            if let Some(certificate) = potential_certificate {
                debug!("Commit {:?}", certificate);
                // NOTE: This log entry is used to compute performance.
                info!("Commit {}", certificate);

                // Serialize the certificate.
                let message = IdPToWitnessMessage::PublishCertificate(certificate);
                let serialized =
                    bincode::serialize(&message).expect("Failed to serialize certificate");

                // Send it to the synchronizer and ensure it is correctly stored.
                let (sender, receiver) = oneshot::channel();
                let message = NewCertificate {
                    sequence_number,
                    certificate: serialized.clone(),
                    ack: sender,
                };
                self.tx_certificate
                    .send(message)
                    .await
                    .expect("Failed to deliver certificate");
                receiver.await.expect("Failed to ack new certificate");

                // Broadcast the certificate to the witnesses.
                let bytes = Bytes::from(serialized);
                let handles = self
                    .network
                    .broadcast(self.addresses.clone(), bytes)
                    .await
                    .into_iter()
                    .zip(self.names.iter().cloned())
                    .collect();

                // Stop waiting for votes.
                return handles;
            }
        }
        panic!("Failed to gather quorum of votes");
    }

    /// Analyses the witnesses response to IdP's publishes certificates.
    async fn analyze_state_response(&mut self, reply: Bytes, author: PublicKey) {
        // Deserialize the reply.
        let message: WitnessToIdPMessage = match bincode::deserialize(&reply) {
            Ok(x) => x,
            Err(e) => {
                warn!("{:?}", e);
                return;
            }
        };

        // Parse the reply.
        match message {
            WitnessToIdPMessage::State(Ok(..)) => (),
            WitnessToIdPMessage::State(Err(WitnessError::MissingEarlierCertificates(s))) => {
                debug!("{} is outdated (latest sequence number: {})", author, s);
                let message = SyncTrigger {
                    target: author,
                    retry: None,
                    sequence_number: s,
                };
                self.tx_trigger
                    .send(message)
                    .await
                    .expect("Failed to deliver sync trigger");
            }
            WitnessToIdPMessage::State(Err(e)) => warn!("{}", e),
            _ => warn!("{}", IdpError::UnexpectedProtocolMessage),
        }
    }

    /// Main loop receiving new notifications to publish.
    async fn run(&mut self) {
        // Gather certificates handles to receive state ack.
        // TODO: Make this memory-bound (like the synchronizer). A bad witness can make us run out
        // of memory by never replying to our certificates.
        let mut state_responses = FuturesUnordered::new();

        loop {
            tokio::select! {
                // Receive serialized publish notifications.
                Some(notification) = self.rx_notification.recv() => self
                    .publish(notification)
                    .await
                    .into_iter()
                    .for_each(|(handle, author)| state_responses.push(Self::waiter(handle, author))),

                // Receive state ack from the witnesses.
                Some((reply, author)) = state_responses.next() => self
                    .analyze_state_response(reply,author)
                    .await,
            }
        }
    }
}
