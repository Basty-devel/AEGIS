//! Bounded cache of skipped-message keys, so a message that arrives
//! out of order still decrypts (design §5). Adopts Signal's algorithm
//! directly: keyed by `(sender_ratchet_ecdh_public, message_number)`,
//! bounded to `MAX_SKIP` entries (Signal's own default), FIFO eviction
//! past the bound, single-use (a key is [`SkippedKeyCache::remove`]d
//! once it has actually authenticated a message — lookups themselves
//! ([`SkippedKeyCache::peek`]) never mutate the cache, so a message
//! that fails AEAD authentication leaves it untouched).

use crate::kdf_chain::MESSAGE_KEY_LEN;
use crate::prekey::ECDH_PUBLIC_KEY_LEN;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Signal's own reference `MAX_SKIP` default
/// (<https://signal.org/docs/specifications/doubleratchet/#deferring-key-derivation>).
pub const MAX_SKIP: usize = 1000;

pub(crate) type CacheKey = ([u8; ECDH_PUBLIC_KEY_LEN], u32);

pub(crate) struct SkippedKeyCache {
    // `insertion_order` tracks FIFO eviction order; `entries` is the
    // actual lookup table. A `HashMap` alone has no defined iteration
    // order to evict by, hence the parallel `VecDeque`.
    entries: HashMap<CacheKey, Zeroizing<[u8; MESSAGE_KEY_LEN]>>,
    insertion_order: std::collections::VecDeque<CacheKey>,
}

impl SkippedKeyCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: std::collections::VecDeque::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        sender_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        message_number: u32,
        key: Zeroizing<[u8; MESSAGE_KEY_LEN]>,
    ) {
        let cache_key = (sender_ratchet_ecdh_public, message_number);
        if self.entries.insert(cache_key, key).is_none() {
            self.insertion_order.push_back(cache_key);
        }
        while self.insertion_order.len() > MAX_SKIP {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// Look a key up **without** consuming it.
    ///
    /// Deliberately separate from [`Self::remove`]: `decrypt` must be
    /// able to try a cached key against a message's AEAD tag and leave
    /// the cache byte-for-byte untouched if that fails (final-review
    /// finding C2 — no state change may be a side effect of a message
    /// that ultimately fails authentication). Removing on lookup and
    /// re-inserting on failure would *almost* do that, but it also
    /// moves the entry to the back of `insertion_order`, silently
    /// changing its FIFO eviction priority.
    pub(crate) fn peek(
        &self,
        sender_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        message_number: u32,
    ) -> Option<&Zeroizing<[u8; MESSAGE_KEY_LEN]>> {
        self.entries.get(&(sender_ratchet_ecdh_public, message_number))
    }

    /// Consume a cached key. Each skipped key is single-use (design
    /// §5), so this runs only once the key has actually been used to
    /// authenticate a message successfully.
    pub(crate) fn remove(
        &mut self,
        sender_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        message_number: u32,
    ) -> Option<Zeroizing<[u8; MESSAGE_KEY_LEN]>> {
        let cache_key = (sender_ratchet_ecdh_public, message_number);
        let key = self.entries.remove(&cache_key)?;
        self.insertion_order.retain(|k| k != &cache_key);
        Some(key)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate all entries currently cached, in FIFO (insertion) order —
    /// used by `RatchetState::to_bytes` to produce a deterministic,
    /// reproducible serialization regardless of `HashMap`'s own
    /// iteration order.
    pub(crate) fn iter_in_insertion_order(
        &self,
    ) -> impl Iterator<Item = (CacheKey, &Zeroizing<[u8; MESSAGE_KEY_LEN]>)> {
        self.insertion_order.iter().filter_map(move |cache_key| {
            self.entries.get(cache_key).map(|key| (*cache_key, key))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_remove_returns_the_key() {
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        cache.insert(sender, 3, [0xAAu8; 32].into());
        let key = cache.remove(sender, 3).unwrap();
        assert_eq!(*key, [0xAAu8; 32]);
    }

    #[test]
    fn remove_consumes_the_entry() {
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        cache.insert(sender, 3, [0xAAu8; 32].into());
        assert!(cache.remove(sender, 3).is_some());
        assert!(cache.remove(sender, 3).is_none(), "a matched key must be single-use");
    }

    #[test]
    fn peek_does_not_consume_the_entry() {
        // Final-review finding C2: decrypt tries a cached key against
        // the AEAD tag before knowing whether it will authenticate, so
        // the lookup itself must not mutate the cache.
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        cache.insert(sender, 3, [0xAAu8; 32].into());
        assert_eq!(**cache.peek(sender, 3).unwrap(), [0xAAu8; 32]);
        assert_eq!(**cache.peek(sender, 3).unwrap(), [0xAAu8; 32]);
        assert_eq!(cache.len(), 1, "peek must leave the entry in place");
    }

    #[test]
    fn lookup_misses_for_an_unknown_key() {
        let mut cache = SkippedKeyCache::new();
        assert!(cache.peek([0x01u8; 129], 0).is_none());
        assert!(cache.remove([0x01u8; 129], 0).is_none());
    }

    #[test]
    fn different_senders_with_the_same_message_number_are_distinct() {
        let mut cache = SkippedKeyCache::new();
        let sender_a = [0x01u8; 129];
        let sender_b = [0x02u8; 129];
        cache.insert(sender_a, 0, [0xAAu8; 32].into());
        cache.insert(sender_b, 0, [0xBBu8; 32].into());
        assert_eq!(*cache.remove(sender_a, 0).unwrap(), [0xAAu8; 32]);
        assert_eq!(*cache.remove(sender_b, 0).unwrap(), [0xBBu8; 32]);
    }

    #[test]
    fn insertion_past_the_bound_evicts_the_oldest_entry() {
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        for n in 0..MAX_SKIP as u32 {
            cache.insert(sender, n, [n as u8; 32].into());
        }
        assert_eq!(cache.len(), MAX_SKIP);

        cache.insert(sender, MAX_SKIP as u32, [0xFFu8; 32].into());
        assert_eq!(cache.len(), MAX_SKIP, "must stay at the bound, not grow past it");
        assert!(cache.remove(sender, 0).is_none(), "oldest entry (message 0) must have been evicted");
        assert!(cache.remove(sender, MAX_SKIP as u32).is_some(), "newest entry must still be present");
    }
}
