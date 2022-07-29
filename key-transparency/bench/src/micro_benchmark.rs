mod utils;

use crate::utils::publish_multi_epoch;
use vkd::storage::memory::AsyncInMemoryDatabase;
use vkd::AkdLabel;
use vkd::AkdValue;
use config::Committee;
use crypto::KeyPair;
use futures::executor::block_on;
use messages::{
    publish::{PublishCertificate, PublishNotification, PublishVote},
    Root,
};
use statistical::{mean, standard_deviation};
use std::time::Instant;
use storage::vkd_storage::AkdStorage;
use test_utils::{certificate, committee, keys, notification, votes};
use utils::{display_file_sizes, proof, proof_with_storage, publish_with_storage_stats};

use crate::utils::{generate_key_entries, publish_with_storage};

const AKD_STORAGE_PATH: &str = ".micro_benchmark_vkd_storage";

/// The default number of runs used to compute statistics.
const DEFAULT_RUNS: u64 = 10;

/// The default number measures to constitute a run (to smooth bootstrapping).
const DEFAULT_PRECISION: u64 = 1;

/// The number of key-values pair in the state tree.
const DEFAULT_NUM_TREE_ENTRIES: u64 = 1_000;

const KEY_ENTRY_BATCH_SIZES: &'static [u64] =
    &[2_u64.pow(5), 2_u64.pow(7), 2_u64.pow(10), 2_u64.pow(15)];

/// Number of key entries in a large batch
const LARGE_BATCH_SIZE: u64 = 100_000;

const NUM_EPOCHS: u64 = 100;

/// Run micro-benchmarks for every CPU-intensive operation.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let num_tree_entries = match args.len() {
        x if x > 1 => args[1].parse().unwrap_or(DEFAULT_NUM_TREE_ENTRIES),
        _ => DEFAULT_NUM_TREE_ENTRIES,
    };
    println!("Starting micro-benchmarks:");

    // // Run all micro-benchmarks.
    // create_notification(num_tree_entries);
    // verify_notification(num_tree_entries);
    // create_vote();
    // verify_vote();
    // aggregate_certificate();
    // verify_certificate();
    // publish_with_different_batch_sizes(true);
    // publish_with_different_batch_sizes(false);
    // // AKD in-memory storage implementations don't have stats as of now. Disabling this one.
    // // storage_stats_with_different_batch_sizes(true);
    // // RocksDB stats.
    // storage_stats_with_different_batch_sizes(false);
    block_on(publish_multi_epoch(LARGE_BATCH_SIZE, NUM_EPOCHS));
}

/// Run a single micro-benchmark.
/// The `setup` function is executed before starting the timer and produces all the parameters needed for the
/// benchmark. The `run` function is executed multiple times using the setup data (as references).
fn bench<Setup, Run, Data, Result>(id: &str, setup: Setup, run: Run, num_runs: u64, precision: u64)
where
    Setup: FnOnce() -> Data,
    Run: Fn(&Data) -> Result,
{
    // Get the setup parameters.
    let inputs = setup();

    // Run the function to benchmark a number of times.
    let mut data = Vec::new();
    for _ in 0..num_runs {
        let now = Instant::now();
        for _ in 0..precision {
            let _result = run(&inputs);
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / precision as f64);
    }

    // Display the results to stdout.
    println!(
        "  {:>7.2} +/- {:<5.2} ms {:.>50}",
        mean(&data),
        standard_deviation(&data, None),
        id
    );
}

/// Benchmark the creation of a publish notification.
fn create_notification(tree_entries: u64) {
    struct Data(KeyPair);

    let setup = || {
        let (_, keypair) = keys().pop().unwrap();
        Data(keypair)
    };

    let run = |data: &Data| {
        let Data(keypair) = data;

        let _ = std::fs::remove_dir_all(&AKD_STORAGE_PATH);
        let db = AkdStorage::new(AKD_STORAGE_PATH);
        let (_, root, proof) = block_on(proof_with_storage(tree_entries, db));
        PublishNotification::new(root, proof, 1, keypair)
    };

    bench(
        "create notification",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
    let _ = std::fs::remove_dir_all(&AKD_STORAGE_PATH);
}

/// Wrapper around publish with multiple batch sizes.
fn publish_with_different_batch_sizes(use_in_memory_db: bool) {
    for batch_size in KEY_ENTRY_BATCH_SIZES {
        publish(*batch_size, use_in_memory_db);
    }
}

/// Benchmark the publish operation given different number of keys to publish.
fn publish(num_tree_entries: u64, use_in_memory_db: bool) {
    struct Data(Vec<(AkdLabel, AkdValue)>);
    // Prepare key entries to be used for the bench.
    let setup = || Data(generate_key_entries(num_tree_entries));

    let run = |data: &Data| {
        let Data(key_entries) = data;

        // Decide what type of database to use (in-memory or persistent).
        if use_in_memory_db {
            let db = AsyncInMemoryDatabase::new();
            block_on(publish_with_storage(key_entries.to_vec(), db));
        } else {
            // Clean up database file pre-bench.
            let _ = std::fs::remove_dir_all(&AKD_STORAGE_PATH);

            let db = AkdStorage::new(AKD_STORAGE_PATH);
            block_on(publish_with_storage(key_entries.to_vec(), db));
        }
    };

    // Construct bench id to display.
    let db_type_prefix = if use_in_memory_db {
        "in_memory"
    } else {
        "persistent"
    };
    let bench_id = format!("publish_batch_size_{}_{}", num_tree_entries, db_type_prefix);

    // Bench!
    bench(&bench_id, setup, run, DEFAULT_RUNS, 1);

    // Bench clean up.
    let _ = std::fs::remove_dir_all(&AKD_STORAGE_PATH);
}

/// Wrapper for storage stats of multiple batch sizes.
fn storage_stats_with_different_batch_sizes(use_in_memory_db: bool) {
    for batch_size in KEY_ENTRY_BATCH_SIZES {
        storage_stats(*batch_size, use_in_memory_db);
    }
}

/// Prints storage stats info after publishing given number of keys.
fn storage_stats(num_tree_entries: u64, use_in_memory_db: bool) {
    if use_in_memory_db {
        let db = AsyncInMemoryDatabase::new();
        block_on(publish_with_storage_stats(num_tree_entries, db));
    } else {
        let _ = std::fs::remove_dir_all(&AKD_STORAGE_PATH);

        let db = AkdStorage::new(AKD_STORAGE_PATH);
        println!("***********************************************************");

        block_on(publish_with_storage_stats(num_tree_entries, db));
        // Show storage stats.
        display_file_sizes(&AKD_STORAGE_PATH);

        println!("***********************************************************");

        // Clean up post-publish
        let _ = std::fs::remove_dir_all(&AKD_STORAGE_PATH);
    }
}

/// Benchmark the verification of a publish notification.
fn verify_notification(tree_entries: u64) {
    struct Data(PublishNotification, Committee, Root);

    let setup = || {
        let (_, keypair) = keys().pop().unwrap();
        let (_, root, proof) = block_on(proof(tree_entries));
        let notification = PublishNotification::new(root, proof, 1, &keypair);
        Data(notification, committee(0), Root::default())
    };

    let run = |data: &Data| {
        let Data(notification, committee, previous_root) = data;
        block_on(notification.verify(committee, previous_root))
    };

    bench(
        "verify notification",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
}

/// Benchmark the creation of a publish vote.
fn create_vote() {
    struct Data(PublishNotification, KeyPair);

    let setup = || {
        let (_, keypair) = keys().pop().unwrap();
        Data(block_on(notification()), keypair)
    };

    let run = |data: &Data| {
        let Data(notification, keypair) = data;
        PublishVote::new(notification, keypair)
    };

    bench("create vote", setup, run, DEFAULT_RUNS, DEFAULT_PRECISION);
}

/// Benchmark the verification of a publish vote.
fn verify_vote() {
    struct Data(PublishVote, Committee);

    let setup = || {
        let vote = block_on(votes()).pop().unwrap();
        Data(vote, committee(0))
    };

    let run = |data: &Data| {
        let Data(vote, committee) = data;
        vote.verify(committee)
    };

    bench("verify vote", setup, run, DEFAULT_RUNS, DEFAULT_PRECISION);
}

/// Benchmark the aggregation of a quorum of votes into a certificate.
fn aggregate_certificate() {
    struct Data(PublishNotification, Vec<PublishVote>);

    let setup = || {
        let threshold = committee(0).quorum_threshold() as usize;
        let mut votes = block_on(votes());
        votes.truncate(threshold);
        Data(block_on(notification()), votes)
    };

    let run = |data: &Data| {
        let Data(notification, votes) = data;
        PublishCertificate {
            root: notification.root,
            sequence_number: notification.sequence_number,
            votes: votes
                .iter()
                .map(|x| (x.author, x.signature.clone()))
                .collect(),
        }
    };

    bench(
        "aggregate certificate",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
}

/// Benchmark the verification of a certificate.
fn verify_certificate() {
    struct Data(PublishCertificate, Committee);

    let setup = || {
        let threshold = committee(0).quorum_threshold() as usize;
        let mut certificate = block_on(certificate());
        certificate.votes.truncate(threshold);
        Data(certificate, committee(0))
    };

    let run = |data: &Data| {
        let Data(certificate, committee) = data;
        certificate.verify(committee)
    };

    bench(
        "verify certificate",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
}
