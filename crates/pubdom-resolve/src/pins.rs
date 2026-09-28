//! The pin file: `pubdom_core::pins::PinSnapshot` as pretty JSON, written
//! atomically (temp file + rename) on every change. Same schema on every
//! platform (docs/plan-platforms.md §5); the phone writes it in its private
//! files dir, the daemon under `/var/lib/fips-pubdom/`.

use pubdom_core::pins::{Binding, MemoryPinStore, PinSnapshot, PinStore, SeenKey};
use std::io;
use std::path::{Path, PathBuf};

pub struct FilePinStore {
    path: PathBuf,
    mem: MemoryPinStore,
}

impl FilePinStore {
    /// Load `path` if it exists (a missing file is an empty store; a corrupt
    /// one is an error — better to stop than to silently drop every pin).
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let snap = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<PinSnapshot>(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => PinSnapshot::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { path, mem: MemoryPinStore::from_snapshot(snap) })
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
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.mem.snapshot()).map_err(io::Error::other)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)
    }
}

impl PinStore for FilePinStore {
    fn get(&self, domain: &str) -> Option<Binding> {
        self.mem.get(domain)
    }
    fn put(&self, binding: Binding) {
        self.mem.put(binding);
        self.save();
    }
    fn forget(&self, domain: &str) {
        self.mem.forget(domain);
        self.save();
    }
    fn list(&self) -> Vec<Binding> {
        self.mem.list()
    }
    fn newest_seen(&self, key: &SeenKey) -> Option<u64> {
        self.mem.newest_seen(key)
    }
    fn note_seen(&self, key: SeenKey, created_at: u64) {
        self.mem.note_seen(key, created_at);
        self.save();
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
        assert_eq!(again.get("example.org").unwrap().verified_at, 42);
        again.forget("example.org");
        assert!(FilePinStore::open(&path).unwrap().list().is_empty());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(FilePinStore::open(&path).is_err(), "corruption is loud");
        let _ = std::fs::remove_dir_all(dir);
    }
}
