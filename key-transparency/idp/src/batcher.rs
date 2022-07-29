use bytes::Bytes;
use log::{debug, warn};
use messages::update::Batch;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
    time::{sleep, Duration, Instant},
};

/// Assemble clients requests into batches.
pub struct Batcher {
    /// The preferred batch size (in bytes).
    batch_size: usize,
    /// The maximum delay after which to seal the batch (in ms).
    max_batch_delay: u64,
    /// Channel to receive requests from the network.
    rx_request: Receiver<Bytes>,
    /// Output channel to deliver sealed batches to the `NotificationMaker`.
    tx_batch: Sender<Batch>,
    /// Holds the current batch.
    current_batch: Batch,
    /// Holds the size of the current batch (in bytes).
    current_batch_size: usize,
}

impl Batcher {
    /// Spawn a new `Batcher` task.
    pub fn spawn(
        batch_size: usize,
        max_batch_delay: u64,
        rx_request: Receiver<Bytes>,
        tx_batch: Sender<Batch>,
    ) -> JoinHandle<()> {
        #[cfg(feature = "benchmark")]
        // NOTE: These log entries are used to compute performance.
        log::info!("batch size set to {}", batch_size);

        tokio::spawn(async move {
            Self {
                batch_size,
                max_batch_delay,
                rx_request,
                tx_batch,
                current_batch: Vec::with_capacity(2 * batch_size),
                current_batch_size: 0,
            }
            .run()
            .await
        })
    }

    /// Main loop receiving incoming requests and creating batches.
    async fn run(&mut self) {
        let timer = sleep(Duration::from_millis(self.max_batch_delay));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                // Assemble client requests into batches of preset size.
                Some(bytes) = self.rx_request.recv() => {
                    let update = match bincode::deserialize(&bytes) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!("Failed to deserialize request: {}", e);
                            continue;
                        }
                    };

                    self.current_batch_size += 1;
                    self.current_batch.push(update);
                    if self.current_batch_size >= self.batch_size {
                        self.seal().await;
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                    }
                },

                // If the timer triggers, seal the batch even if it contains few transactions.
                () = &mut timer => {
                    if !self.current_batch.is_empty() {
                        debug!("Timer triggered, sealing batch early");
                        #[cfg(feature = "benchmark")]
                        // NOTE: These log entries are used to compute performance.
                        warn!("Timer triggered, sealing batch early");

                        self.seal().await;
                    }
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                }
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// Seal the current batch.
    async fn seal(&mut self) {
        self.current_batch_size = 0;
        let batch: Batch = self.current_batch.drain(..).collect();
        self.tx_batch
            .send(batch)
            .await
            .expect("Failed to deliver batch");
    }
}
