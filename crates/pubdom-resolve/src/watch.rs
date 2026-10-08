//! Following files as something else rewrites them, debounced: the
//! daemon's upstreams file (systemd-resolved and NetworkManager rewrite
//! their resolv.conf when a network comes or goes, so a change there *is*
//! the network-change signal, without netlink) and the server's zones
//! directory (a zone added, edited or removed by an operator, or by the
//! fips-ui helper). The caller keeps a poll as the fallback and re-tries
//! the watch while it is missing — a directory may not exist yet at start.
//!
//! For a file, its directory is watched, not the file: resolvers write a
//! new file and rename it into place, which would leave a watch on the old
//! inode deaf.

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
    let w = watch_in(
        &dir,
        move |p| p.file_name() == Some(name.as_os_str()),
        on_change,
    )?;
    tracing::info!(file = %target.display(), "following the file for changes");
    Some(w)
}

/// Call `on_change` whenever anything in `dir` (not below it) is created,
/// written, renamed or removed, debounced. Same contract as [`watch`].
pub fn watch_dir<F: Fn() + Send + 'static>(
    dir: &Path,
    on_change: F,
) -> Option<Debouncer<notify::RecommendedWatcher>> {
    let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let w = watch_in(&dir, |_| true, on_change)?;
    tracing::info!(dir = %dir.display(), "following the directory for changes");
    Some(w)
}

/// The watch on `dir`, reporting the events `wanted` picks.
fn watch_in<P, F>(
    dir: &Path,
    wanted: P,
    on_change: F,
) -> Option<Debouncer<notify::RecommendedWatcher>>
where
    P: Fn(&Path) -> bool + Send + 'static,
    F: Fn() + Send + 'static,
{
    let mut debouncer = match new_debouncer(SETTLE, move |res: Result<Vec<DebouncedEvent>, _>| {
        if let Ok(events) = res
            && events.iter().any(|e| wanted(&e.path))
        {
            on_change();
        }
    }) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "cannot watch for changes; polling only");
            return None;
        }
    };
    if let Err(e) = debouncer.watcher().watch(dir, RecursiveMode::NonRecursive) {
        tracing::warn!(dir = %dir.display(), error = %e, "cannot watch the directory; polling only");
        return None;
    }
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
        // Let the watcher settle, and discard anything it replays from
        // before it started (FSEvents on macOS reports recent history).
        std::thread::sleep(SETTLE * 3);
        hits.store(0, Ordering::SeqCst);
        // Another file in the directory is not our change — not asserted:
        // FSEvents coalesces directory activity, and a library crate has
        // no platform-specific code, tests included (docs/platforms.md).
        std::fs::write(dir.0.join("stub-resolv.conf"), "nameserver 127.0.0.53\n").unwrap();
        std::thread::sleep(SETTLE * 3);
        hits.store(0, Ordering::SeqCst);
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

    #[test]
    fn a_directory_watch_sees_a_file_added_and_removed() {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "pubdom-watchdir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
        std::fs::create_dir_all(&dir.0).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let _w = watch_dir(&dir.0, move || {
            h.fetch_add(1, Ordering::SeqCst);
        })
        .expect("a watcher on a temporary directory");
        std::thread::sleep(SETTLE * 3);
        hits.store(0, Ordering::SeqCst);
        std::fs::write(dir.0.join("example.org.yaml"), "domain: example.org\n").unwrap();
        assert!(settled(&hits) >= 1, "the new file was seen");
        hits.store(0, Ordering::SeqCst);
        std::fs::remove_file(dir.0.join("example.org.yaml")).unwrap();
        assert!(settled(&hits) >= 1, "the removal was seen");
    }
}
