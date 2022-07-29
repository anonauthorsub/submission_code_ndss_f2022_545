use vkd::{AkdLabel, AkdValue};
use anyhow::{anyhow, ensure, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use clap::{arg, crate_name, crate_version, Arg, Command};
use config::{Committee, Import};
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use log::{info, warn};
use network::reliable_sender::ReliableSender;
use tokio::{
    net::TcpStream,
    time::{interval, sleep, Duration, Instant},
};

/// The default size of an update request (key + value).
const DEFAULT_UPDATE_SIZE: usize = 64;

#[tokio::main]
async fn main() -> Result<()> {
    // Read the cli parameters.
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Key Transparency witnesses.")
        .arg(Arg::new("verbose").multiple_occurrences(true).short('v'))
        .args(&[
            arg!(--committee <FILE> "The path to the committee file"),
            arg!(--rate <INT> "The rate (txs/s) at which to send the transactions"),
            arg!(--size [INT] "The size (B) of an update key + value"),
            arg!(--faults [INT] "The number of crash-faults"),
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
    let committee_file = matches.value_of("committee").unwrap();
    let committee = Committee::import(committee_file).context("Failed to load committee")?;

    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;

    let size = matches
        .value_of("size")
        .unwrap_or(&format!("{}", DEFAULT_UPDATE_SIZE))
        .parse::<usize>()
        .context("The size of update requests must be a non-negative integer")?;

    let faults = matches
        .value_of("faults")
        .unwrap_or("0")
        .parse::<usize>()
        .context("The number of crash-faults must be a non-negative integer")?;
    ensure!(
        faults < committee.size(),
        anyhow!("The number of faults should be less than the committee size")
    );

    // Make a benchmark client.
    let client = BenchmarkClient::new(committee, rate, size, faults);
    client.print_parameters();

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client
        .benchmark()
        .await
        .context("Failed to submit transactions")
}

/// A client only useful for benchmarks.
pub struct BenchmarkClient {
    /// The committee information.
    committee: Committee,
    /// The number of requests per seconds that this client submits.
    rate: u64,
    /// The size of an update (key + value).
    size: usize,
    /// The number of crash-faults.
    faults: usize,
}

impl BenchmarkClient {
    /// Creates a new benchmark client.
    pub fn new(committee: Committee, rate: u64, size: usize, faults: usize) -> Self {
        Self {
            committee,
            rate,
            size,
            faults,
        }
    }

    /// Log the benchmark parameters required to compute performance.
    pub fn print_parameters(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Transactions rate: {} tx/s", self.rate);
        info!("Target idp address: {}", self.committee.idp.address);
    }

    /// Wait for all authorities to be online.
    pub async fn wait(&self) {
        info!("Waiting for the IdP and all witnesses to be online...");
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
        let mut counter = 0;

        let mut network = ReliableSender::new();
        let address = self.committee.idp.address;
        let mut key = BytesMut::with_capacity(self.size);
        let value = AkdValue(vec![0; self.size]);
        let mut pending = FuturesUnordered::new();

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
                        key.put_u64(id);
                        key.resize(self.size, 0u8);
                        let label = AkdLabel(key.split().freeze().to_vec());

                        let update = (label, value.clone());
                        let bytes = Bytes::from(bincode::serialize(&update).unwrap());

                        let handle = network.send(address, bytes).await;
                        pending.push(handle);

                        // NOTE: This log entry is used to compute performance.
                        info!("Sending sample transaction {}", id);
                    }
                    counter += 1;

                    if now.elapsed().as_millis() > BURST_DURATION as u128 {
                        // NOTE: This log entry is used to compute performance.
                        warn!("Transaction rate too high for this client");
                    }
                }
                Some(_) = pending.next() => {
                    // Sink acknowledgements.
                },
                else => break
            }
        }
        Ok(())
    }
}
