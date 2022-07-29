use crypto::{KeyPair, PublicKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufWriter, Write as _},
    net::SocketAddr,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file '{file}': {message}")]
    ImportError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    ExportError { file: String, message: String },
}

/// Read from file a configuration.
pub trait Import: DeserializeOwned {
    fn import(path: &str) -> Result<Self, ConfigError> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| ConfigError::ImportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

/// Write to file a configuration (in JSON format).
pub trait Export: Serialize {
    fn export(&self, path: &str) -> Result<(), ConfigError> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| ConfigError::ExportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

/// Denomination of the voting power of each witness.
pub type VotingPower = u32;

/// The public information of the IdP.
#[derive(Clone, Deserialize)]
pub struct Idp {
    /// The public key of the Idp.
    pub name: PublicKey,
    /// The network addresses to receive client update requests.
    pub address: SocketAddr,
}

/// The public information of a witness.
#[derive(Clone, Deserialize)]
pub struct Witness {
    /// The voting power of this witness.
    pub voting_power: VotingPower,
    /// The network addresses of the witness.
    pub address: SocketAddr,
}

/// The (public) committee information.
#[derive(Clone, Deserialize)]
pub struct Committee {
    pub idp: Idp,
    pub witnesses: BTreeMap<PublicKey, Witness>,
}

impl Import for Committee {}

impl Committee {
    /// Return the number of witnesses.
    pub fn size(&self) -> usize {
        self.witnesses.len()
    }

    /// Return the voting power of a specific witness.
    pub fn voting_power(&self, name: &PublicKey) -> VotingPower {
        self.witnesses
            .get(name)
            .map_or_else(|| 0, |x| x.voting_power)
    }

    /// Returns the stake required to reach a quorum (2f+1).
    pub fn quorum_threshold(&self) -> VotingPower {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: VotingPower = self.witnesses.values().map(|x| x.voting_power).sum();
        2 * total_votes / 3 + 1
    }

    /// Returns the stake required to reach availability (f+1).
    pub fn validity_threshold(&self) -> VotingPower {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        let total_votes: VotingPower = self.witnesses.values().map(|x| x.voting_power).sum();
        (total_votes + 2) / 3
    }

    /// Returns the addresses of all witnesses.
    pub fn witness_address(&self, name: &PublicKey) -> Option<SocketAddr> {
        self.witnesses.get(name).map(|witness| witness.address)
    }

    /// Returns the addresses of all witnesses.
    pub fn witnesses_addresses(&self) -> Vec<(PublicKey, SocketAddr)> {
        self.witnesses
            .iter()
            .map(|(name, witness)| (*name, witness.address))
            .collect()
    }
}

/// The private configuration of the identity provider and witnesses.
#[derive(Serialize, Deserialize)]
pub struct PrivateConfig {
    /// The public key of this entity.
    pub name: PublicKey,
    /// The private key of this entity.
    pub secret: KeyPair,
}

impl Default for PrivateConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateConfig {
    /// Creates a new private configuration.
    pub fn new() -> Self {
        let (name, secret) = KeyPair::generate_production_keypair();
        Self { name, secret }
    }
}

impl Import for PrivateConfig {}
impl Export for PrivateConfig {}
