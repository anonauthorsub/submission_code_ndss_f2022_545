use crate::Replier;
use messages::{
    sync::PublishCertificateQuery, SequenceNumber, SerializedPublishCertificateMessage,
    WitnessToIdPMessage,
};
use storage::Storage;
use tokio::sync::mpsc::Receiver;

/// Task dedicated to help other witnesses to sync up by replying to certificate requests.
pub struct SyncHelper {
    /// The persistent storage.
    storage: Storage,
    /// Received serialized publish certificates once processed by the publish handler.
    rx_processed_certificate: Receiver<(SerializedPublishCertificateMessage, SequenceNumber)>,
    /// Receive the publish certificates requests.
    rx_certificate_request: Receiver<(PublishCertificateQuery, Replier)>,
}

impl SyncHelper {
    /// Spawn a new sync helper task.
    pub fn spawn(
        storage: Storage,
        rx_processed_certificate: Receiver<(SerializedPublishCertificateMessage, SequenceNumber)>,
        rx_certificate_request: Receiver<(PublishCertificateQuery, Replier)>,
    ) {
        tokio::spawn(async move {
            Self {
                storage,
                rx_processed_certificate,
                rx_certificate_request,
            }
            .run()
            .await
        });
    }

    /// Main loop answering certificate requests.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                // Store new certificates.
                Some((serialized_certificate, sequence_number)) = self.rx_processed_certificate.recv() => {
                    let key = sequence_number.to_le_bytes();
                    self
                        .storage
                        .write(&key, &serialized_certificate)
                        .expect("Failed to persist certificate");
                },

                // Serve certificates to whoever asks for them.
                Some((request, replier)) = self.rx_certificate_request.recv() => {
                    // Check whether the requested certificate is in storage.
                    let key = request.sequence_number.to_le_bytes();
                    if let Some(serialized_certificate) = self
                        .storage
                        .read(&key)
                        .expect("Failed to load certificate from storage")
                    {
                        // Reply with the certificate (if we have it).
                        let reply = WitnessToIdPMessage::PublishCertificateResponse(serialized_certificate);
                        replier
                            .send(reply)
                            .expect("Failed to reply to certificate sync request");
                    }
                }
            }
        }
    }
}
