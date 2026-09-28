//! TTL caches for the items of spec §5.6. Time is passed in, never read.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

/// Legacy TXT miss (no binding): most domains have none.
pub const TXT_MISS_TTL: Duration = Duration::from_secs(6 * 3600);
/// Legacy TXT hit: min(record TTL, this).
pub const TXT_HIT_MAX_TTL: Duration = Duration::from_secs(3600);
/// Upstreams disagreed on the TXT record: ask again soon, a rollover
/// settles within the record's TTL.
pub const TXT_DISPUTED_TTL: Duration = Duration::from_secs(60);
/// Relay miss offline (no claim): once per domain, not per query.
pub const RELAY_MISS_TTL: Duration = Duration::from_secs(3600);
/// Claims fetched from relays.
pub const CLAIM_TTL: Duration = Duration::from_secs(3600);
/// Step 3 answers: min(answer TTL, this).
pub const STEP3_MAX_TTL: Duration = Duration::from_secs(3600);

pub struct TtlCache<K, V> {
    inner: Mutex<HashMap<K, (u64, V)>>,
    max_entries: usize,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// `now` in seconds, same clock as `put`.
    pub fn get(&self, key: &K, now: u64) -> Option<V> {
        let g = self.inner.lock().unwrap();
        let (expires, v) = g.get(key)?;
        (*expires > now).then(|| v.clone())
    }

    pub fn put(&self, key: K, value: V, ttl: Duration, now: u64) {
        let mut g = self.inner.lock().unwrap();
        if g.len() >= self.max_entries {
            // Cheap pressure valve: drop everything expired, then if still
            // full drop an arbitrary entry. DNS caches survive being lossy.
            g.retain(|_, (exp, _)| *exp > now);
            if g.len() >= self.max_entries
                && let Some(k) = g.keys().next().cloned()
            {
                g.remove(&k);
            }
        }
        g.insert(key, (now.saturating_add(ttl.as_secs()), value));
    }

    pub fn remove(&self, key: &K) {
        self.inner.lock().unwrap().remove(key);
    }

    /// Remove the entry only if it is live and `pred` holds for its value,
    /// atomically. An expired entry is left for the next pressure sweep;
    /// `get` already ignores it.
    pub fn remove_if(&self, key: &K, now: u64, pred: impl FnOnce(&V) -> bool) {
        let mut g = self.inner.lock().unwrap();
        if g.get(key).is_some_and(|(exp, v)| *exp > now && pred(v)) {
            g.remove(key);
        }
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn remove_if_only_removes_live_matching_entries() {
        let c: TtlCache<u8, bool> = TtlCache::new(8);
        c.put(1, true, Duration::from_secs(10), 100);
        c.put(2, false, Duration::from_secs(10), 100);
        c.remove_if(&1, 105, |v| *v);
        c.remove_if(&2, 105, |v| *v);
        assert_eq!(c.get(&1, 105), None);
        assert_eq!(c.get(&2, 105), Some(false));
        // Expired: left alone, and still invisible.
        c.put(3, true, Duration::from_secs(1), 100);
        c.remove_if(&3, 200, |_| true);
        assert_eq!(c.get(&3, 200), None);
    }

    use super::*;

    #[test]
    fn expires_and_bounds() {
        let c: TtlCache<&str, u8> = TtlCache::new(2);
        c.put("a", 1, Duration::from_secs(10), 100);
        assert_eq!(c.get(&"a", 105), Some(1));
        assert_eq!(c.get(&"a", 110), None, "expiry is exclusive");
        c.put("b", 2, Duration::from_secs(10), 100);
        c.put("c", 3, Duration::from_secs(10), 100);
        let g = c.inner.lock().unwrap();
        assert!(g.len() <= 2);
    }
}
