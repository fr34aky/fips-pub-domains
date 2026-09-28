//! The pin file: `pubdom_core::pins::PinSnapshot` as pretty JSON, written
//! atomically (temp file + rename) on every change. Same schema on every
//! platform (docs/platforms.md); the phone writes it in its private
//! files dir, the daemon under `/var/lib/fips-pubdom/`.

use pubdom_core::pins::{Binding, MemoryPinStore, PinSnapshot, PinStore, SeenKey};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct FilePinStore {
    path: PathBuf,
    mem: MemoryPinStore,
    /// Saves are serialized: two concurrent lookups pinning different
    /// domains would otherwise race on the temp file and could leave a
    /// truncated pin file behind, which refuses to load.
    saving: Mutex<()>,
    seq: AtomicU64,
}

impl FilePinStore {
    /// Load `path` if it exists (a missing file is an empty store; a corrupt
    /// one is an error — better to stop than to silently drop every pin).
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let snap = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<PinSnapshot>(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => PinSnapshot::default(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            mem: MemoryPinStore::from_snapshot(snap),
            saving: Mutex::new(()),
            seq: AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) {
        if let Err(e) = self.try_save() {
            tracing::error!(path = %self.path.display(), error = %e, "could not write pin file");
        }
    }

    fn try_save(&self) -> io::Result<()> {
        let _serialized = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .path
            .with_extension(format!("json.{}.{n}.tmp", std::process::id()));
        let bytes = serde_json::to_vec_pretty(&self.mem.snapshot()).map_err(io::Error::other)?;
        let result = std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, &self.path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

impl PinStore for FilePinStore {
    fn get(&self, domain: &str) -> Vec<Binding> {
        self.mem.get(domain)
    }
    fn put(&self, binding: Binding) -> bool {
        let changed = self.mem.put(binding);
        if changed {
            self.save();
        }
        changed
    }
    fn forget(&self, domain: &str) -> bool {
        let changed = self.mem.forget(domain);
        if changed {
            self.save();
        }
        changed
    }
    fn forget_server(&self, domain: &str, npub: pubdom_core::Npub) -> bool {
        let changed = self.mem.forget_server(domain, npub);
        if changed {
            self.save();
        }
        changed
    }
    fn list(&self) -> Vec<Binding> {
        self.mem.list()
    }
    fn newest_seen(&self, key: &SeenKey) -> Option<u64> {
        self.mem.newest_seen(key)
    }
    fn note_seen(&self, key: SeenKey, created_at: u64) -> bool {
        let changed = self.mem.note_seen(key, created_at);
        if changed {
            self.save();
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubdom_core::{Method, Npub};

    #[test]
    fn persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("fips-pubdom-pins-{}", std::process::id()));
        let path = dir.join("pins.json");
        let store = FilePinStore::open(&path).unwrap();
        store.put(Binding {
            domain: "example.org".into(),
            npub: Npub::from_bytes([1; 32]),
            port: 5355,
            method: Method::Dnssec,
            verified_at: 42,
        });
        let again = FilePinStore::open(&path).unwrap();
        assert_eq!(again.get("example.org")[0].verified_at, 42);
        again.forget("example.org");
        assert!(FilePinStore::open(&path).unwrap().list().is_empty());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(FilePinStore::open(&path).is_err(), "corruption is loud");
        let _ = std::fs::remove_dir_all(dir);
    }
}
