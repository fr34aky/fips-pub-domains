//! TTL caches for the items of spec §5.6. Time is passed in, never read.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

/// Legacy TXT miss (no binding): most domains have none.
pub const TXT_MISS_TTL: Duration = Duration::from_secs(6 * 3600);
/// Legacy TXT hit: min(record TTL, this).
pub const TXT_HIT_MAX_TTL: Duration = Duration::from_secs(3600);
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
        Self { inner: Mutex::new(HashMap::new()), max_entries }
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
            if g.len() >= self.max_entries {
                if let Some(k) = g.keys().next().cloned() {
                    g.remove(&k);
                }
            }
        }
        g.insert(key, (now.saturating_add(ttl.as_secs()), value));
    }

    pub fn remove(&self, key: &K) {
        self.inner.lock().unwrap().remove(key);
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
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
