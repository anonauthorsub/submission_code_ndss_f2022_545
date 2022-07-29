// Copyright (c) Anonymous Authors of NDSS Submission #545.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Code for an auditor of a authenticated key directory

use std::marker::{Send, Sync};

use winter_crypto::Hasher;

use crate::{
    errors::{VkdError, AuditorError, OzksError},
    proof_structs::{AppendOnlyProof, SingleAppendOnlyProof},
    storage::memory::AsyncInMemoryDatabase,
    Ozks,
};

/// Verifies an audit proof, given start and end hashes for a merkle patricia tree.
pub async fn audit_verify<H: Hasher + Send + Sync>(
    hashes: Vec<H::Digest>,
    proof: AppendOnlyProof<H>,
) -> Result<(), VkdError> {
    if proof.epochs.len() + 1 != hashes.len() {
        return Err(VkdError::AuditErr(AuditorError::VerifyAuditProof(format!(
            "The proof has a different number of epochs than needed for hashes. 
            The number of hashes you provide should be one more than the number of epochs! 
            Number of epochs = {}, number of hashes = {}",
            proof.epochs.len(),
            hashes.len()
        ))));
    }
    if proof.epochs.len() != proof.proofs.len() {
        return Err(VkdError::AuditErr(AuditorError::VerifyAuditProof(format!(
            "The proof has {} epochs and {} proofs. These should be equal!",
            proof.epochs.len(),
            proof.proofs.len()
        ))));
    }
    for i in 0..hashes.len() - 1 {
        let start_hash = hashes[i];
        let end_hash = hashes[i + 1];
        verify_consecutive_append_only::<H>(
            &proof.proofs[i],
            start_hash,
            end_hash,
            proof.epochs[i] + 1,
        )
        .await?;
    }
    Ok(())
}

/// Helper for audit, verifies an append-only proof
pub async fn verify_consecutive_append_only<H: Hasher + Send + Sync>(
    proof: &SingleAppendOnlyProof<H>,
    start_hash: H::Digest,
    end_hash: H::Digest,
    epoch: u64,
) -> Result<(), VkdError> {
    // FIXME: Need to get rid of the clone here. Will need modifications to the functions called here.
    let unchanged_nodes = proof.unchanged_nodes.clone();
    let inserted = proof.inserted.clone();

    let db = AsyncInMemoryDatabase::new();
    let mut ozks = Ozks::new::<_, H>(&db).await?;
    ozks.batch_insert_leaves_helper::<_, H>(&db, unchanged_nodes, true)
        .await?;
    let computed_start_root_hash: H::Digest = ozks.get_root_hash::<_, H>(&db).await?;
    let mut verified = computed_start_root_hash == start_hash;
    ozks.latest_epoch = epoch - 1;
    let updated_inserted = inserted
        .iter()
        .map(|x| {
            let mut y = *x;
            y.hash = H::merge_with_int(x.hash, epoch);
            y
        })
        .collect();
    ozks.batch_insert_leaves_helper::<_, H>(&db, updated_inserted, true)
        .await?;
    let computed_end_root_hash: H::Digest = ozks.get_root_hash::<_, H>(&db).await?;
    verified = verified && (computed_end_root_hash == end_hash);
    if !verified {
        return Err(VkdError::OzksErr(OzksError::VerifyAppendOnlyProof));
    }
    Ok(())
}
