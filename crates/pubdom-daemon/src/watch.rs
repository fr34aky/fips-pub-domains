//! Following the upstreams file as the OS rewrites it: systemd-resolved and
//! NetworkManager both rewrite their resolv.conf when a network comes or
//! goes, so a change there *is* the network-change signal, on every Linux
//! backend alike and without netlink. The 30 s poll stays as the fallback
//! for a filesystem the watcher cannot cover.
//!
//! The directory is watched, not the file: both resolvers write a new file
//! and rename it into place, which would leave a watch on the old inode
//! deaf.

use notify::{RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Events closer together than this are one change: a rewrite is several
/// filesystem events, and a network change several rewrites.
const SETTLE: Duration = Duration::from_millis(300);

/// Call `on_change` whenever something in `path`'s directory changes,
/// debounced. Returns the watcher, which stops when dropped; `None` when
/// the path has no directory or the platform cannot watch it, in which
/// case the caller's poll is all there is.
pub fn watch<F: Fn() + Send + 'static>(path: &Path, on_change: F) -> Option<impl Drop> {
    let dir = path.parent()?.to_path_buf();
    let (tx, rx) = mpsc::channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = tx.send(());
        }
    })
    .ok()?;
    watcher.watch(&dir, RecursiveMode::NonRecursive).ok()?;
    std::thread::Builder::new()
        .name("pubdom-upstreams-watch".into())
        .spawn(move || {
            while rx.recv().is_ok() {
                // Let the burst settle, then drain what arrived meanwhile.
                std::thread::sleep(SETTLE);
                while rx.try_recv().is_ok() {}
                on_change();
            }
        })
        .ok()?;
    tracing::info!(dir = %dir.display(), "following the upstreams file for changes");
    Some(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_rewrite_in_the_directory_is_one_change() {
        let dir = std::env::temp_dir().join(format!(
            "pubdom-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("resolv.conf");
        std::fs::write(&file, "nameserver 10.0.0.1\n").unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let _w = watch(&file, move || {
            h.fetch_add(1, Ordering::SeqCst);
        })
        .expect("a watcher on a temporary directory");
        // As resolved does it: write a new file, rename it into place.
        std::thread::sleep(Duration::from_millis(200));
        let tmp = dir.join(".resolv.conf.tmp");
        std::fs::write(&tmp, "nameserver 10.0.0.2\n").unwrap();
        std::fs::rename(&tmp, &file).unwrap();
        let start = std::time::Instant::now();
        while hits.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the write and the rename settled into one change"
        );
        // Quiet afterwards: no change, no call.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_without_a_directory_cannot_be_watched() {
        assert!(watch(Path::new("/"), || {}).is_none());
    }
}
