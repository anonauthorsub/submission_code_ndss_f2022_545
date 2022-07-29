use config::{Committee, VotingPower};
use crypto::{PublicKey, Signature};
use messages::{
    ensure,
    error::{IdpError, IdpResult, MessageError},
    publish::{PublishCertificate, PublishVote},
    Root,
};
use std::collections::HashSet;

/// Aggregates votes into a certificate.
pub struct Aggregator {
    /// The committee information.
    committee: Committee,
    /// The root to certify.
    root: Root,
    /// The current voting power accumulated for this root.
    weight: VotingPower,
    /// The list of votes' signatures.
    votes: Vec<(PublicKey, Signature)>,
    /// The set of witness that already voted.
    used: HashSet<PublicKey>,
}

impl Aggregator {
    /// Initialize a new aggregator.
    pub fn new(committee: Committee, root: Root) -> Self {
        Self {
            committee,
            root,
            weight: VotingPower::default(),
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Reset the aggregator.
    pub fn reset(&mut self, root: Root) {
        self.root = root;
        self.weight = 0;
        self.votes.clear();
        self.used.clear();
    }

    /// Append a vote to the aggregator.
    pub fn append(&mut self, vote: PublishVote) -> IdpResult<Option<PublishCertificate>> {
        let author = vote.author;
        let voting_power = self.committee.voting_power(&author);

        // Ensure the vote is for the correct root.
        ensure!(
            self.root == vote.root,
            IdpError::UnexpectedVote {
                expected: self.root,
                received: vote.root
            }
        );

        // Ensure the witness is in the committee.
        ensure!(
            voting_power > 0,
            IdpError::MessageError(MessageError::UnknownWitness(author))
        );

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            IdpError::MessageError(MessageError::WitnessReuse(author))
        );

        // Verify the vote.
        vote.verify(&self.committee)?;

        // Check if we have a quorum.
        self.votes.push((author, vote.signature));
        self.weight += voting_power;
        if self.weight >= self.committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(PublishCertificate {
                root: vote.root,
                sequence_number: vote.sequence_number,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::{committee, votes};

    #[tokio::test]
    async fn make_certificate() {
        let mut votes = votes().await;
        let root = votes[0].root;
        let sequence_number = votes[0].sequence_number;
        let mut aggregator = Aggregator::new(committee(0), root);

        // Add a quorum of votes.
        let vote_0 = votes.pop().unwrap();
        let result = aggregator.append(vote_0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let vote_1 = votes.pop().unwrap();
        let result = aggregator.append(vote_1);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let vote_2 = votes.pop().unwrap();
        let result = aggregator.append(vote_2);
        assert!(result.is_ok());

        // Verify the resulting certificate.
        let certificate = result.unwrap().unwrap();
        assert!(certificate.verify(&committee(0)).is_ok());
        assert_eq!(certificate.root, root);
        assert_eq!(certificate.sequence_number, sequence_number);
    }
}
