use borsh::{BorshDeserialize, BorshSerialize};
use nmt_rs::{NamespaceId, NamespaceProof, NamespacedSha2Hasher};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlobTransactionTrait;

use crate::types::FilteredCelestiaBlock;

use super::CelestiaSpec;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub struct EtxProof {
    pub proof: Vec<EtxRangeProof>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub struct EtxRangeProof {
    pub shares: Vec<Vec<u8>>,
    pub proof: NamespaceProof<NamespacedSha2Hasher>,
    pub start_share_idx: usize,
    pub start_offset: usize,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub struct RelevantRowProof {
    pub leaves: Vec<Vec<u8>>,
    pub proof: NamespaceProof<NamespacedSha2Hasher>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct CompletenessProof(pub Vec<RelevantRowProof>);

impl CompletenessProof {
    pub fn from_filtered_block(block: &FilteredCelestiaBlock, namespace: NamespaceId) -> Self {
        let mut row_proofs = Vec::new();
        for row in block.rollup_rows.iter() {
            let mut nmt = row.merklized();
            let (leaves, proof) = nmt.get_namespace_with_proof(namespace);
            let row_proof = RelevantRowProof { leaves, proof };
            row_proofs.push(row_proof)
        }
        Self(row_proofs)
    }
}

pub struct CorrectnessProof(pub Vec<EtxProof>);

impl CorrectnessProof {
    pub fn for_block(
        block: &FilteredCelestiaBlock,
        blobs: &[<CelestiaSpec as sov_rollup_interface::da::DaSpec>::BlobTransaction],
    ) -> Self {
        let mut needed_tx_shares = Vec::new();

        // Extract (and clone) the position of each transaction
        for tx in blobs.iter() {
            // We process the transaction only if we read something from it
            if tx.data().counter() != 0 {
                let (_, position) = block
                    .relevant_pfbs
                    .get(tx.hash.as_slice())
                    .expect("commitment must exist in map");
                needed_tx_shares.push(position.clone());
            }
        }

        let mut needed_tx_shares = needed_tx_shares.into_iter().peekable();
        let mut current_tx_proof: EtxProof = EtxProof { proof: Vec::new() };
        let mut tx_proofs: Vec<EtxProof> = Vec::with_capacity(blobs.len());

        for (row_idx, row) in block.pfb_rows.iter().enumerate() {
            let mut nmt = row.merklized();
            while let Some(next_needed_share) = needed_tx_shares.peek_mut() {
                // If the next needed share falls in this row
                let row_start_idx = block.square_size() * row_idx;
                let start_column_number = next_needed_share.share_range.start - row_start_idx;
                if start_column_number < block.square_size() {
                    let end_column_number = next_needed_share.share_range.end - row_start_idx;
                    if end_column_number <= block.square_size() {
                        let (shares, proof) =
                            nmt.get_range_with_proof(start_column_number..end_column_number);

                        current_tx_proof.proof.push(EtxRangeProof {
                            shares,
                            proof,
                            start_offset: next_needed_share.start_offset,
                            start_share_idx: next_needed_share.share_range.start,
                        });
                        tx_proofs.push(current_tx_proof);
                        current_tx_proof = EtxProof { proof: Vec::new() };
                        let _ = needed_tx_shares.next();
                    } else {
                        let (shares, proof) =
                            nmt.get_range_with_proof(start_column_number..block.square_size());

                        current_tx_proof.proof.push(EtxRangeProof {
                            shares,
                            proof,
                            start_offset: next_needed_share.start_offset,
                            start_share_idx: next_needed_share.share_range.start,
                        });
                        next_needed_share.share_range.start = block.square_size() * (row_idx + 1);
                        next_needed_share.start_offset = 0;

                        break;
                    }
                } else {
                    break;
                }
            }
        }
        Self(tx_proofs)
    }
}
