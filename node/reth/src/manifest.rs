//! Block manifest (format 3) and the single-file segment that stores it.
//!
//! A manifest is the replay evidence of one block: the decoded identity
//! envelope and outcome of every transaction (in block order), the id of the
//! durable fact record list the candidate pinned, and the exact signed lease
//! (an embedded heartbeat, or else the last record's own header). It never
//! stores what the block itself carries (transaction hashes, network).
//!
//! A segment is `[entry]* [index row]* footer`. Each entry is one zstd frame
//! of one manifest. Index rows are sorted by (number, hash) and carry each
//! entry's offset, length, SHA-256, record-list id, fact versions and block
//! timestamp, so a lookup reads the footer, the index and one entry
//! (positional reads, never the whole segment), and compaction, pruning and
//! fact-record collection work from indexes alone. The footer checksums the
//! index. A produced block is published as a one-entry segment; compaction
//! copies finalized entries' frames, unchanged, into many-entry segments.

use crate::{archive::ArtifactId, context::CreatedContract, wire::SignedEnvelope};
use alloy_primitives::{Address, B256};
use sha2::{Digest, Sha256};

const ENTRY_MAGIC: &[u8; 8] = b"OPSMAN03";
const SEGMENT_MAGIC: &[u8; 8] = b"OPSSEG03";
const ROW: usize = 8 + 32 + 8 + 4 + 32 + 32 + 8 + 8 + 8;
/// Bytes of a segment footer.
pub const FOOTER: usize = 8 + 4 + 8 + 32;
/// Decoded size accepted for one manifest. Reading never allocates more than
/// the frame's declared content size, and never more than this.
const MAX_DECODED: u64 = 1 << 30;
const LEVEL: i32 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub envelope: SignedEnvelope,
    pub success: bool,
    pub reason_code: String,
    pub created: Vec<CreatedContract>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockManifest {
    pub hash: B256,
    pub parent_hash: B256,
    pub number: u64,
    pub timestamp: u64,
    pub facts_version: u64,
    /// The version of the snapshot the fact chain starts from: every record
    /// the record list names has at least this version.
    pub base_version: u64,
    pub facts_digest: B256,
    /// The durable record-list object the candidate's facts were built from.
    pub records: ArtifactId,
    /// The heartbeat that made the facts fresh at `timestamp`, if one renewed
    /// the lease; otherwise the last record's own header is the lease.
    pub lease: Option<SignedEnvelope>,
    pub entries: Vec<ManifestEntry>,
}

/// One row of a segment index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexRow {
    pub number: u64,
    pub hash: B256,
    pub offset: u64,
    pub length: u32,
    pub checksum: B256,
    pub records: ArtifactId,
    pub facts_version: u64,
    pub base_version: u64,
    pub timestamp: u64,
}

fn invalid() -> String {
    "invalid execution manifest".into()
}

struct Writer(Vec<u8>);
impl Writer {
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: usize) -> Result<(), String> {
        let value = u16::try_from(value).map_err(|_| invalid())?;
        self.bytes(&value.to_be_bytes());
        Ok(())
    }
    fn u32(&mut self, value: usize) -> Result<(), String> {
        let value = u32::try_from(value).map_err(|_| invalid())?;
        self.bytes(&value.to_be_bytes());
        Ok(())
    }
    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    fn short(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.u16(bytes.len())?;
        self.bytes(bytes);
        Ok(())
    }
    fn long(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.u32(bytes.len())?;
        self.bytes(bytes);
        Ok(())
    }
    fn envelope(&mut self, envelope: &SignedEnvelope) -> Result<(), String> {
        self.short(envelope.key_id.as_bytes())?;
        self.long(&envelope.payload)?;
        self.bytes(&envelope.signature);
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        if self.0.len() < length {
            return Err(invalid());
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("exact length"))
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<usize, String> {
        Ok(u16::from_be_bytes(self.array()?) as usize)
    }
    fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_be_bytes(self.array()?) as usize)
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn b256(&mut self) -> Result<B256, String> {
        Ok(B256::from(self.array::<32>()?))
    }
    fn flag(&mut self) -> Result<bool, String> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        }
    }
    fn text(&mut self) -> Result<String, String> {
        let length = self.u16()?;
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| invalid())
    }
    fn envelope(&mut self, kind: &str) -> Result<SignedEnvelope, String> {
        let key_id = self.text()?;
        let length = self.u32()?;
        let payload = self.take(length)?.to_vec();
        Ok(SignedEnvelope {
            kind: kind.into(),
            key_id,
            payload,
            signature: self.array()?,
        })
    }
    fn finish(&self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

impl BlockManifest {
    /// Exact binary encoding (uncompressed).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.base_version == 0 || self.base_version > self.facts_version {
            return Err(invalid());
        }
        let mut out = Writer(Vec::with_capacity(256 + self.entries.len() * 768));
        out.bytes(ENTRY_MAGIC);
        out.bytes(self.hash.as_slice());
        out.bytes(self.parent_hash.as_slice());
        out.u64(self.number);
        out.u64(self.timestamp);
        out.u64(self.facts_version);
        out.u64(self.base_version);
        out.bytes(self.facts_digest.as_slice());
        out.bytes(self.records.as_b256().as_slice());
        match &self.lease {
            None => out.u8(0),
            Some(lease) => {
                if lease.kind != "heartbeat" {
                    return Err(invalid());
                }
                out.u8(1);
                out.envelope(lease)?;
            }
        }
        out.u32(self.entries.len())?;
        for entry in &self.entries {
            if entry.envelope.kind != "identity" {
                return Err(invalid());
            }
            out.envelope(&entry.envelope)?;
            out.u8(entry.success as u8);
            out.short(entry.reason_code.as_bytes())?;
            out.u16(entry.created.len())?;
            for created in &entry.created {
                out.bytes(created.address.as_slice());
                out.short(created.org_id.as_bytes())?;
                out.short(created.principal_id.as_bytes())?;
            }
        }
        Ok(out.0)
    }

    /// Strict inverse of `encode`: every byte consumed, nothing left over.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut input = Reader(bytes);
        if input.take(8)? != ENTRY_MAGIC {
            return Err(invalid());
        }
        let hash = input.b256()?;
        let parent_hash = input.b256()?;
        let number = input.u64()?;
        let timestamp = input.u64()?;
        let facts_version = input.u64()?;
        let base_version = input.u64()?;
        if base_version == 0 || base_version > facts_version {
            return Err(invalid());
        }
        let facts_digest = input.b256()?;
        let records = ArtifactId::from_b256(input.b256()?);
        let lease = match input.flag()? {
            false => None,
            true => Some(input.envelope("heartbeat")?),
        };
        let count = input.u32()?;
        // Every entry takes at least this many bytes: bound the allocation.
        if count > input.0.len() / (2 + 4 + 64 + 1 + 2 + 2) + 1 {
            return Err(invalid());
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let envelope = input.envelope("identity")?;
            let success = input.flag()?;
            let reason_code = input.text()?;
            let created = (0..input.u16()?)
                .map(|_| {
                    Ok(CreatedContract {
                        address: Address::from(input.array::<20>()?),
                        org_id: input.text()?,
                        principal_id: input.text()?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            entries.push(ManifestEntry {
                envelope,
                success,
                reason_code,
                created,
            });
        }
        input.finish()?;
        Ok(Self {
            hash,
            parent_hash,
            number,
            timestamp,
            facts_version,
            base_version,
            facts_digest,
            records,
            lease,
            entries,
        })
    }
}

/// Encode manifests as one segment file. Rows are sorted by (number, hash);
/// duplicates are refused.
pub fn write_segment(manifests: &[&BlockManifest]) -> Result<Vec<u8>, String> {
    let entries = manifests
        .iter()
        .map(|manifest| {
            let frame = zstd::bulk::compress(&manifest.encode()?, LEVEL).map_err(|_| invalid())?;
            Ok((row_for(manifest, &frame)?, frame))
        })
        .collect::<Result<Vec<_>, String>>()?;
    assemble_segment(entries)
}

/// The index row of `manifest` stored as `frame` (offset filled in later).
fn row_for(manifest: &BlockManifest, frame: &[u8]) -> Result<IndexRow, String> {
    Ok(IndexRow {
        number: manifest.number,
        hash: manifest.hash,
        offset: 0,
        length: u32::try_from(frame.len()).map_err(|_| invalid())?,
        checksum: B256::from_slice(&Sha256::digest(frame)),
        records: manifest.records,
        facts_version: manifest.facts_version,
        base_version: manifest.base_version,
        timestamp: manifest.timestamp,
    })
}

/// A segment from already verified (row, frame) entries: compaction copies
/// frames unchanged. Rows are sorted by (number, hash) and offsets assigned;
/// duplicates and mismatched rows are refused.
pub fn assemble_segment(mut entries: Vec<(IndexRow, Vec<u8>)>) -> Result<Vec<u8>, String> {
    entries.sort_by_key(|(row, _)| (row.number, row.hash));
    if entries.is_empty()
        || entries
            .windows(2)
            .any(|pair| (pair[0].0.number, pair[0].0.hash) == (pair[1].0.number, pair[1].0.hash))
    {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(
        entries.iter().map(|(_, frame)| frame.len()).sum::<usize>() + entries.len() * ROW + FOOTER,
    );
    let mut rows = Vec::with_capacity(entries.len());
    for (mut row, frame) in entries {
        if row.length as usize != frame.len()
            || B256::from_slice(&Sha256::digest(&frame)) != row.checksum
        {
            return Err(invalid());
        }
        row.offset = out.len() as u64;
        out.extend_from_slice(&frame);
        rows.push(row);
    }
    let index_offset = out.len() as u64;
    let start = out.len();
    for row in &rows {
        out.extend_from_slice(&row.number.to_be_bytes());
        out.extend_from_slice(row.hash.as_slice());
        out.extend_from_slice(&row.offset.to_be_bytes());
        out.extend_from_slice(&row.length.to_be_bytes());
        out.extend_from_slice(row.checksum.as_slice());
        out.extend_from_slice(row.records.as_b256().as_slice());
        out.extend_from_slice(&row.facts_version.to_be_bytes());
        out.extend_from_slice(&row.base_version.to_be_bytes());
        out.extend_from_slice(&row.timestamp.to_be_bytes());
    }
    let index_checksum = Sha256::digest(&out[start..]);
    out.extend_from_slice(SEGMENT_MAGIC);
    out.extend_from_slice(&(u32::try_from(rows.len()).map_err(|_| invalid())?).to_be_bytes());
    out.extend_from_slice(&index_offset.to_be_bytes());
    out.extend_from_slice(&index_checksum);
    Ok(out)
}

/// Where a segment's index is: (row count, index offset, index checksum),
/// from its footer, for a segment of `size` bytes.
fn parse_footer(footer: &[u8], size: u64) -> Result<(usize, u64, B256), String> {
    if footer.len() != FOOTER {
        return Err(invalid());
    }
    let mut footer = Reader(footer);
    if footer.take(8)? != SEGMENT_MAGIC {
        return Err(invalid());
    }
    let count = footer.u32()?;
    let index_offset = footer.u64()?;
    let checksum = footer.b256()?;
    let index_end = size.checked_sub(FOOTER as u64).ok_or_else(invalid)?;
    if count == 0
        || index_offset > index_end
        || index_end - index_offset != (count as u64).checked_mul(ROW as u64).ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    Ok((count, index_offset, checksum))
}

/// The verified rows of an index read from `index_offset`.
fn parse_index(
    index: &[u8],
    count: usize,
    index_offset: u64,
    checksum: B256,
) -> Result<Vec<IndexRow>, String> {
    if index.len() != count * ROW || B256::from_slice(&Sha256::digest(index)) != checksum {
        return Err(invalid());
    }
    let mut input = Reader(index);
    let mut rows: Vec<IndexRow> = Vec::with_capacity(count);
    for _ in 0..count {
        let row = IndexRow {
            number: input.u64()?,
            hash: input.b256()?,
            offset: input.u64()?,
            length: input.u32()? as u32,
            checksum: input.b256()?,
            records: ArtifactId::from_b256(input.b256()?),
            facts_version: input.u64()?,
            base_version: input.u64()?,
            timestamp: input.u64()?,
        };
        let end = row
            .offset
            .checked_add(row.length as u64)
            .ok_or_else(invalid)?;
        let previous_end = rows
            .last()
            .map(|previous| previous.offset + previous.length as u64)
            .unwrap_or(0);
        if row.offset != previous_end
            || end > index_offset
            || row.base_version == 0
            || row.base_version > row.facts_version
            || rows
                .last()
                .is_some_and(|previous| (previous.number, previous.hash) >= (row.number, row.hash))
        {
            return Err(invalid());
        }
        rows.push(row);
    }
    if rows.last().map(|row| row.offset + row.length as u64) != Some(index_offset) {
        return Err(invalid());
    }
    Ok(rows)
}

/// The verified index of a segment held in memory.
pub fn read_index(segment: &[u8]) -> Result<Vec<IndexRow>, String> {
    if segment.len() < FOOTER {
        return Err(invalid());
    }
    let size = segment.len() as u64;
    let (count, index_offset, checksum) = parse_footer(&segment[segment.len() - FOOTER..], size)?;
    parse_index(
        &segment[index_offset as usize..segment.len() - FOOTER],
        count,
        index_offset,
        checksum,
    )
}

/// The verified index of a segment of `size` bytes through positional reads
/// (`read(offset, length)`): the footer, then the index; never the entries.
pub fn read_index_at(
    read: &dyn Fn(u64, usize) -> Result<Vec<u8>, String>,
    size: u64,
) -> Result<Vec<IndexRow>, String> {
    let footer_at = size.checked_sub(FOOTER as u64).ok_or_else(invalid)?;
    let (count, index_offset, checksum) = parse_footer(&read(footer_at, FOOTER)?, size)?;
    let length = usize::try_from(footer_at - index_offset).map_err(|_| invalid())?;
    parse_index(&read(index_offset, length)?, count, index_offset, checksum)
}

/// One entry's frame, checked against its row.
pub fn read_frame_at(
    read: &dyn Fn(u64, usize) -> Result<Vec<u8>, String>,
    row: &IndexRow,
) -> Result<Vec<u8>, String> {
    let frame = read(row.offset, row.length as usize)?;
    if frame.len() != row.length as usize
        || B256::from_slice(&Sha256::digest(&frame)) != row.checksum
    {
        return Err(invalid());
    }
    Ok(frame)
}

/// Decode a verified frame and check it is the manifest its row names.
pub fn decode_frame(frame: &[u8], row: &IndexRow) -> Result<BlockManifest, String> {
    if B256::from_slice(&Sha256::digest(frame)) != row.checksum {
        return Err(invalid());
    }
    // Exactly one frame, of exactly the row's length.
    if zstd::zstd_safe::find_frame_compressed_size(frame).ok() != Some(frame.len()) {
        return Err(invalid());
    }
    let size = zstd::zstd_safe::get_frame_content_size(frame)
        .ok()
        .flatten()
        .filter(|size| *size <= MAX_DECODED)
        .ok_or_else(invalid)? as usize;
    let decoded = zstd::bulk::decompress(frame, size).map_err(|_| invalid())?;
    if decoded.len() != size {
        return Err(invalid());
    }
    let manifest = BlockManifest::decode(&decoded)?;
    if manifest.number != row.number
        || manifest.hash != row.hash
        || manifest.records != row.records
        || manifest.facts_version != row.facts_version
        || manifest.base_version != row.base_version
        || manifest.timestamp != row.timestamp
    {
        return Err(invalid());
    }
    Ok(manifest)
}

/// The manifest of block (number, hash) in an in-memory `segment`, if present.
pub fn read_entry(
    segment: &[u8],
    number: u64,
    hash: B256,
) -> Result<Option<BlockManifest>, String> {
    let rows = read_index(segment)?;
    let Ok(position) = rows.binary_search_by_key(&(number, hash), |row| (row.number, row.hash))
    else {
        return Ok(None);
    };
    let row = &rows[position];
    decode_frame(
        &segment[row.offset as usize..(row.offset + row.length as u64) as usize],
        row,
    )
    .map(Some)
}

/// The manifest of block (number, hash) in a segment of `size` bytes, through
/// positional reads: footer, index, then that one entry.
pub fn read_entry_at(
    read: &dyn Fn(u64, usize) -> Result<Vec<u8>, String>,
    size: u64,
    number: u64,
    hash: B256,
) -> Result<Option<BlockManifest>, String> {
    let rows = read_index_at(read, size)?;
    let Ok(position) = rows.binary_search_by_key(&(number, hash), |row| (row.number, row.hash))
    else {
        return Ok(None);
    };
    let row = &rows[position];
    decode_frame(&read_frame_at(read, row)?, row).map(Some)
}
