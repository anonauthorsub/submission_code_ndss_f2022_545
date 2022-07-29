use anyhow::{Context, Result};
use clap::{arg, crate_name, crate_version, Arg, ArgMatches, Command};
use config::{Committee, Export, Import, PrivateConfig};
use storage::Storage;
use witness::spawn_witness;

#[tokio::main]
async fn main() -> Result<()> {
    // Read the cli parameters.
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .about("A Key Transparency witnesses.")
        .arg(Arg::new("verbose").multiple_occurrences(true).short('v'))
        .subcommand(
            Command::new("generate")
                .about("Print a fresh key pair to file")
                .arg(arg!(--filename <FILE> "The path to the witness keypair")),
        )
        .subcommand(Command::new("run").about("Run a witness").args(&[
            arg!(--committee <FILE> "The path to the committee file"),
            arg!(--keypair <FILE> "The path to the witness keypair"),
            arg!(--secure_storage <FILE> "The directory to hold the secure storage"),
            arg!(--audit_storage <FILE> "The directory to hold the audit storage"),
        ]))
        .arg_required_else_help(true)
        .get_matches();

    // Configure the logger.
    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Warn,
        2 => log::LevelFilter::Info,
        3 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .format_timestamp_millis()
        .filter_module("witness", log_level)
        .filter_module("network", log_level)
        .init();

    // Parse the input parameters.
    match matches.subcommand() {
        Some(("generate", sub_matches)) => PrivateConfig::new()
            .export(sub_matches.value_of("filename").unwrap())
            .context("Failed to generate key pair")?,
        Some(("run", sub_matches)) => spawn(sub_matches)
            .await
            .context("Failed to spawn witness")?,
        _ => unreachable!(),
    }
    Ok(())
}

/// Spawn a witness
async fn spawn(matches: &ArgMatches) -> Result<()> {
    let committee_file = matches.value_of("committee").unwrap();
    let committee = Committee::import(committee_file).context("Failed to load committee")?;

    let keypair_file = matches.value_of("keypair").unwrap();
    let keypair = PrivateConfig::import(keypair_file).context("Failed to load keypair")?;

    let secure_storage_file = matches.value_of("secure_storage").unwrap();
    let secure_storage =
        Storage::new(secure_storage_file).context("Failed to create secure storage")?;

    let audit_storage_file = matches.value_of("audit_storage").unwrap();
    let audit_storage =
        Storage::new(audit_storage_file).context("Failed to create audit storage")?;

    // Spawn a witness.
    spawn_witness(keypair.secret, committee, secure_storage, audit_storage);

    // TODO: better way to prevent the program from exiting....
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}
