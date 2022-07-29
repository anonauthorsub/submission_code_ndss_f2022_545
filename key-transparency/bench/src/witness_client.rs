mod utils;

use anyhow::{anyhow, ensure, Context, Result};
use clap::{arg, crate_name, crate_version, Arg, Command};
use config::{Committee, Import, PrivateConfig};
use crypto::KeyPair;
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use log::{debug, info, warn};
use messages::WitnessToIdPMessage;
use network::reliable_sender::ReliableSender;
use std::net::SocketAddr;
use tokio::{
    net::TcpStream,
    time::{interval, sleep, Duration, Instant},
};
use utils::{CertificateGenerator, NotificationGenerator};

#[tokio::main]
async fn main() -> Result<()> {
    // Read the cli parameters.
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Key Transparency witnesses.")
        .arg(Arg::new("verbose").multiple_occurrences(true).short('v'))
        .args(&[
            arg!(--idp <FILE> "The keypair of the IdP"),
            arg!(--committee <FILE> "The path to the committee file"),
            arg!(--rate <INT> "The rate (txs/s) at which to send the transactions"),
            arg!(--faults [INT] "The number of crash-faults"),
            arg!(--proof_entries <INT> "The number of key updates per proof"),
        ])
        .arg_required_else_help(true)
        .get_matches();

    // Configure the logger.
    let log_level = match matches.occurrences_of("verbose") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    // Parse the input parameters.
    let idp_file = matches.value_of("idp").unwrap();
    let idp = PrivateConfig::import(idp_file).context("Failed to load IdP key file")?;

    let committee_file = matches.value_of("committee").unwrap();
    let committee = Committee::import(committee_file).context("Failed to load committee")?;

    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;

    let faults = matches
        .value_of("faults")
        .unwrap_or("0")
        .parse::<usize>()
        .context("The number of crash-faults must be a non-negative integer")?;
    ensure!(
        faults < committee.size(),
        anyhow!("The number of faults should be less than the committee size")
    );

    let proof_entries = matches
        .value_of("proof_entries")
        .unwrap()
        .parse::<u64>()
        .context("The number of key updates per proof must be a non-negative integer")?;

    // Make a benchmark client.
    let client = BenchmarkClient::new(idp.secret, committee, rate, faults, proof_entries);
    client.print_parameters();

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client
        .benchmark()
        .await
        .context("Failed to submit transactions")
}

/// A client only useful to benchmark the witnesses.
pub struct BenchmarkClient {
    /// The key pair of the IdP.
    idp: KeyPair,
    /// The committee information.
    committee: Committee,
    /// The number of requests per seconds that this client submits.
    rate: u64,
    /// The number of crash-faults.
    faults: usize,
    /// The number of key updates per proof.
    proof_entries: u64,
    /// The network address of the witnesses.
    targets: Vec<SocketAddr>,
}

impl BenchmarkClient {
    /// Creates a new benchmark client.
    pub fn new(
        idp: KeyPair,
        committee: Committee,
        rate: u64,
        faults: usize,
        proof_entries: u64,
    ) -> Self {
        let targets: Vec<_> = committee
            .witnesses_addresses()
            .into_iter()
            .map(|(_, x)| x)
            .collect();

        Self {
            idp,
            committee,
            rate,
            faults,
            proof_entries,
            targets,
        }
    }

    /// Log the benchmark parameters required to compute performance.
    pub fn print_parameters(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Batch size: {} proofs/notification", self.proof_entries);
        info!("Transactions rate: {} tx/s", self.rate);
        for target in &self.targets {
            info!("Target witness address: {}", target);
        }
    }

    /// Wait for all authorities to be online.
    pub async fn wait(&self) {
        info!("Waiting for all witnesses to be online...");
        let mut futures: FuturesUnordered<_> = self
            .committee
            .witnesses_addresses()
            .into_iter()
            .chain(std::iter::once((
                self.committee.idp.name,
                self.committee.idp.address,
            )))
            .map(|(_, address)| async move {
                while TcpStream::connect(address).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .collect();

        let expected_nodes = self.committee.size() - self.faults;
        let mut online = 0;
        while futures.next().await.is_some() {
            online += 1;
            if online == expected_nodes {
                break;
            }
        }
    }

    /// Run a benchmark with the provided parameters.
    pub async fn benchmark(&self) -> Result<()> {
        const PRECISION: u64 = 1; // Timing burst precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;
        let burst = self.rate / PRECISION;
        let mut counter = 0; // Identifies sample transactions.

        // Connect to the witnesses.
        let mut network = ReliableSender::new();

        // Initiate the generator of dumb requests.
        let notification_generator =
            NotificationGenerator::new(&self.idp, self.proof_entries).await;
        let mut certificate_generator = CertificateGenerator::new(self.committee.clone());

        // Gather certificates handles to sink their response.
        let mut certificate_responses = FuturesUnordered::new();

        // Submit all transactions.
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    for x in 1..=burst {
                        let id = counter * burst + x;
                        let bytes = notification_generator.make_notification(id);

                        // NOTE: This log entry is used to compute performance.
                        info!("Sending sample transaction {}", id);

                        let mut wait_for_quorum: FuturesUnordered<_> = network
                            .broadcast(self.targets.clone(), bytes)
                            .await
                            .into_iter()
                            .collect();

                        while let Some(bytes) = wait_for_quorum.next().await {
                            let result = match bincode::deserialize(&bytes?)? {
                                WitnessToIdPMessage::PublishVote(result) => result,
                                _ => return Err(anyhow!("Unexpected protocol message"))
                            };
                            let vote = result.context("Witness returned error")?;
                            debug!("{:?}", vote);
                            if let Some(certificate) = certificate_generator.try_make_certificate(vote)
                            {
                                // NOTE: This log entry is used to compute performance.
                                info!("Assembled certificate {}", id);

                                network
                                    .broadcast(self.targets.clone(), certificate)
                                    .await
                                    .into_iter()
                                    .for_each(|handle| certificate_responses.push(handle));

                                certificate_generator.clear();
                                break;
                            }
                        }
                    }
                    counter += 1;

                    if now.elapsed().as_millis() > BURST_DURATION as u128 {
                        // NOTE: This log entry is used to compute performance.
                        warn!("Transaction rate too high for this client");
                    }
                },
                Some(_) = certificate_responses.next() => {
                    // Sink certificates' responses
                },
                else => break
            }
        }
        Ok(())
    }
}
