//! Manifest v2 and segment encoding (plan T29): lossless, compressed, strict.

use alloy_primitives::{Address, B256};
use common::fixture::{AT, identity, seal, verifier};
use ops_reth_policy::{
    archive::ArtifactId,
    context::CreatedContract,
    manifest::{BlockManifest, ManifestEntry, read_entry, read_index, write_segment},
};

mod common;

fn manifest(number: u64, transactions: u64) -> BlockManifest {
    let verifier = verifier();
    BlockManifest {
        hash: B256::from(alloy_primitives::U256::from(number * 1000 + 7)),
        parent_hash: B256::repeat_byte(9),
        number,
        timestamp: AT as u64,
        facts_version: 3,
        base_version: 1,
        facts_digest: B256::repeat_byte(6),
        records: ArtifactId::of(b"record list"),
        lease: Some(
            verifier
                .open_envelope(
                    "heartbeat",
                    &seal(
                        "heartbeat",
                        &serde_json::json!({"network":common::fixture::network(),"issued_at":AT,"expires_at":AT+60,"version":3,"digest":"06".repeat(32)}),
                    ),
                )
                .unwrap(),
        ),
        entries: (0..transactions)
            .map(|index| {
                let hash = B256::from(alloy_primitives::U256::from(index + 1));
                ManifestEntry {
                    envelope: verifier
                        .open_envelope(
                            "identity",
                            &seal("identity", &identity(hash, &format!("ctx-{index}"))),
                        )
                        .unwrap(),
                    success: index % 3 != 0,
                    reason_code: if index % 3 == 0 {
                        "APPLICATION_REVERTED".into()
                    } else {
                        String::new()
                    },
                    created: if index == 1 {
                        vec![CreatedContract {
                            address: Address::repeat_byte(0xab),
                            org_id: "org_acme".into(),
                            principal_id: "fixture_principal".into(),
                        }]
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect(),
    }
}

#[test]
fn compressed_manifest_round_trips_and_signatures_verify() {
    let original = manifest(5, 200);
    let segment = write_segment(&[&original]).unwrap();
    let restored = read_entry(&segment, original.number, original.hash)
        .unwrap()
        .unwrap();
    assert_eq!(restored, original);
    let verifier = verifier();
    for entry in &restored.entries {
        verifier.verify(&entry.envelope).unwrap();
    }
    verifier.verify(restored.lease.as_ref().unwrap()).unwrap();
    let json: usize = original
        .entries
        .iter()
        .map(|entry| entry.envelope.to_wire().len() + 64)
        .sum();
    assert!(
        segment.len() * 3 < json,
        "segment {} B is not compressed against {json} B of JSON envelopes",
        segment.len()
    );
}

#[test]
fn segment_index_finds_each_block_and_rejects_absent_ones() {
    let blocks = [manifest(9, 3), manifest(4, 0), manifest(7, 1)];
    let segment = write_segment(&blocks.iter().collect::<Vec<_>>()).unwrap();
    let rows = read_index(&segment).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.number).collect::<Vec<_>>(),
        vec![4, 7, 9],
        "rows sorted by height"
    );
    assert_eq!(rows[0].records, blocks[1].records);
    for block in &blocks {
        assert_eq!(
            read_entry(&segment, block.number, block.hash)
                .unwrap()
                .as_ref(),
            Some(block)
        );
    }
    assert_eq!(read_entry(&segment, 9, B256::repeat_byte(1)).unwrap(), None);
    assert!(
        write_segment(&[&blocks[0], &blocks[0]]).is_err(),
        "duplicate block"
    );
    assert!(write_segment(&[]).is_err());
}

#[test]
fn damaged_segments_are_refused() {
    let block = manifest(3, 4);
    let segment = write_segment(&[&block]).unwrap();
    let read = |bytes: &[u8]| read_entry(bytes, block.number, block.hash);
    assert!(read(&segment[..segment.len() - 1]).is_err(), "truncated");
    assert!(
        read(&[segment.as_slice(), b"x"].concat()).is_err(),
        "trailing bytes"
    );
    for position in [0, segment.len() / 2, segment.len() - 60, segment.len() - 1] {
        let mut flipped = segment.clone();
        flipped[position] ^= 1;
        assert!(read(&flipped).is_err(), "bit flip at {position}");
    }
    // An entry whose own encoding has trailing bytes is refused even with a
    // valid frame and checksums.
    let mut encoded = block.encode().unwrap();
    encoded.push(0);
    assert!(BlockManifest::decode(&encoded).is_err());
    let truncated = block.encode().unwrap();
    assert!(BlockManifest::decode(&truncated[..truncated.len() - 1]).is_err());
}

/// Recompute the footer's index checksum after editing the index rows.
fn reseal(mut segment: Vec<u8>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let footer = segment.len() - 52;
    let index_offset =
        u64::from_be_bytes(segment[footer + 12..footer + 20].try_into().unwrap()) as usize;
    let checksum = Sha256::digest(&segment[index_offset..footer]);
    segment[footer + 20..].copy_from_slice(&checksum);
    segment
}

#[test]
fn structurally_invalid_segments_are_refused_even_with_valid_checksums() {
    let blocks = [manifest(4, 1), manifest(7, 1)];
    let segment = write_segment(&blocks.iter().collect::<Vec<_>>()).unwrap();
    let footer = segment.len() - 52;
    let index_offset =
        u64::from_be_bytes(segment[footer + 12..footer + 20].try_into().unwrap()) as usize;
    const ROW: usize = 8 + 32 + 8 + 4 + 32 + 32 + 8 + 8 + 8;
    // Swapped rows: unsorted and with offsets out of order.
    let mut swapped = segment.clone();
    let (first, second) = (index_offset, index_offset + ROW);
    let row0 = swapped[first..first + ROW].to_vec();
    let row1 = swapped[second..second + ROW].to_vec();
    swapped[first..first + ROW].copy_from_slice(&row1);
    swapped[second..second + ROW].copy_from_slice(&row0);
    assert!(read_index(&reseal(swapped)).is_err(), "unsorted rows");
    // An offset moved into the previous entry: overlapping entries.
    let mut overlap = segment.clone();
    overlap[second + 40..second + 48].copy_from_slice(&1u64.to_be_bytes());
    assert!(read_index(&reseal(overlap)).is_err(), "overlapping rows");
    // A footer count that disagrees with the index length.
    let mut count = segment.clone();
    count[footer + 8..footer + 12].copy_from_slice(&3u32.to_be_bytes());
    assert!(read_index(&reseal(count)).is_err(), "count mismatch");
    let mut empty = segment.clone();
    empty[footer + 8..footer + 12].copy_from_slice(&0u32.to_be_bytes());
    assert!(read_index(&reseal(empty)).is_err(), "zero entries");
    // A manifest claiming more entries than its bytes can hold is refused
    // before anything is allocated for them.
    let mut bare = manifest(4, 0);
    bare.lease = None;
    let mut encoded = bare.encode().unwrap();
    assert_eq!(encoded.len(), 8 + 32 + 32 + 8 + 8 + 8 + 8 + 32 + 32 + 1 + 4);
    let count = encoded.len() - 4;
    encoded[count..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(BlockManifest::decode(&encoded).is_err());
    assert!(read_index(&reseal(segment.clone())).is_ok(), "control");
}
