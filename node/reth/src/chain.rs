//! What the guarded runtime may treat as final: the canonical block at the
//! lower of Reth's forkchoice-finalized height and the height Reth has
//! written to disk. OPS treats a finalized outcome as permanent (ownership,
//! visibility), so a block a crash can still lose is never reported final
//! or released. Trusted import keeps using consensus finality
//! (`runtime::FinalityView`): persistence does not change what is final.

use alloy_primitives::B256;
use std::{fmt, sync::Mutex};

/// The node's canonical chain as the runtime reads it. Production reads
/// Reth's provider; tests use a model.
pub trait ChainState: Send + Sync + fmt::Debug {
    /// The forkchoice-finalized block, if known.
    fn finalized(&self) -> Option<(u64, B256)>;
    /// The highest canonical block Reth has committed to disk, if known.
    fn persisted(&self) -> Option<u64>;
    /// The canonical hash at `number`.
    fn canonical_hash(&self, number: u64) -> Option<B256>;
    /// The transaction hashes of the canonical block at `number`.
    fn transactions(&self, number: u64) -> Option<Vec<B256>>;
}

/// Effective finality, monotone: once a block was reported final, a later
/// lower reading (a persisted height going back after an unwind, a deferred
/// notification) never un-finalizes it.
#[derive(Debug, Default)]
pub struct Finality {
    high: Mutex<Option<(u64, B256)>>,
}

impl Finality {
    /// Read `chain` and return the effective finalized block.
    pub fn observe(&self, chain: &dyn ChainState) -> Option<(u64, B256)> {
        let reading = Self::read(chain);
        let mut high = self.high.lock().ok()?;
        match (reading, *high) {
            (Some(reading), Some(current)) if reading.0 <= current.0 => {}
            (Some(reading), _) => *high = Some(reading),
            (None, _) => {}
        }
        *high
    }

    /// The last effective finalized block, without reading the chain.
    pub fn current(&self) -> Option<(u64, B256)> {
        *self.high.lock().ok()?
    }

    fn read(chain: &dyn ChainState) -> Option<(u64, B256)> {
        let (finalized, finalized_hash) = chain.finalized()?;
        // A finalized hash that is not canonical at its height (a prospective
        // declaration) proves nothing.
        if chain.canonical_hash(finalized)? != finalized_hash {
            return None;
        }
        let number = finalized.min(chain.persisted()?);
        Some((number, chain.canonical_hash(number)?))
    }
}
