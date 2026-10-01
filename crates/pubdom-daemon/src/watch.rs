//! Following the upstreams file as the OS rewrites it: systemd-resolved and
//! NetworkManager both rewrite their resolv.conf when a network comes or
//! goes, so a change there *is* the network-change signal on those two
//! backends, without netlink. (The dnsmasq and plain-resolv.conf backends
//! point the daemon at a static snapshot, which nothing rewrites.) The
//! 30 s poll stays as the fallback, and re-tries the watch while it is
//! missing — the directory may not exist yet when the daemon starts.
//!
//! The directory is watched, not the file: both resolvers write a new file
//! and rename it into place, which would leave a watch on the old inode
//! deaf.

use notify::RecursiveMode;
use notify_debouncer_mini::{DebouncedEvent, Debouncer, new_debouncer};
use std::path::Path;
use std::time::Duration;

/// Events closer together than this are one change: a rewrite is several
/// filesystem events, and a network change several rewrites.
const SETTLE: Duration = Duration::from_millis(300);

/// Call `on_change` whenever `path` (through any symlink) is written or
/// renamed into place, debounced. The watcher stops when dropped; `None`,
/// with the reason logged, when it cannot be set up — the caller's poll
/// is then all there is until it tries again.
pub fn watch<F: Fn() + Send + 'static>(
    path: &Path,
    on_change: F,
) -> Option<Debouncer<notify::RecommendedWatcher>> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = target.parent()?.to_path_buf();
    let name = target.file_name()?.to_owned();
    let mut debouncer = match new_debouncer(SETTLE, move |res: Result<Vec<DebouncedEvent>, _>| {
        if let Ok(events) = res
            && events
                .iter()
                .any(|e| e.path.file_name() == Some(name.as_os_str()))
        {
            on_change();
        }
    }) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "cannot watch for upstream changes; polling only");
            return None;
        }
    };
    if let Err(e) = debouncer.watcher().watch(&dir, RecursiveMode::NonRecursive) {
        tracing::warn!(dir = %dir.display(), error = %e, "cannot watch the upstreams directory; polling only");
        return None;
    }
    tracing::info!(file = %target.display(), "following the upstreams file for changes");
    Some(debouncer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn settled(hits: &AtomicUsize) -> usize {
        // Wait until the count has been stable for a full settle window.
        let start = std::time::Instant::now();
        let mut last = hits.load(Ordering::SeqCst);
        let mut since = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(6) {
            std::thread::sleep(Duration::from_millis(50));
            let now = hits.load(Ordering::SeqCst);
            if now != last {
                last = now;
                since = std::time::Instant::now();
            } else if last > 0 && since.elapsed() > SETTLE * 3 {
                break;
            }
        }
        last
    }

    #[test]
    fn a_rewrite_of_the_file_is_seen_and_other_files_are_not() {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "pubdom-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
        std::fs::create_dir_all(&dir.0).unwrap();
        let file = dir.0.join("resolv.conf");
        std::fs::write(&file, "nameserver 10.0.0.1\n").unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let _w = watch(&file, move || {
            h.fetch_add(1, Ordering::SeqCst);
        })
        .expect("a watcher on a temporary directory");
        std::thread::sleep(Duration::from_millis(200));
        // Another file in the directory: not our change.
        std::fs::write(dir.0.join("stub-resolv.conf"), "nameserver 127.0.0.53\n").unwrap();
        std::thread::sleep(SETTLE * 3);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a sibling file is not the upstreams file"
        );
        // As resolved does it: write a new file, rename it into place.
        let tmp = dir.0.join(".resolv.conf.tmp");
        std::fs::write(&tmp, "nameserver 10.0.0.2\n").unwrap();
        std::fs::rename(&tmp, &file).unwrap();
        let n = settled(&hits);
        assert!(n >= 1, "the rewrite was seen");
        assert!(
            n <= 2,
            "at most the write and the rename, not one event each: {n}"
        );
    }

    #[test]
    fn a_path_without_a_directory_cannot_be_watched() {
        assert!(watch(Path::new("/"), || {}).is_none());
    }
}
