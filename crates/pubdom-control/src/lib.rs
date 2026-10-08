//! The control socket: how fips-ui (and `fips-pubdom ctl`) talk to a
//! running `fips-pubdomd` or `fips-pubdom-server` (docs/webui.md).
//!
//! The protocol is fips's own, so fips-ui's `control.ts` and `fipsctl`'s
//! client code apply unchanged: a Unix socket, one request per connection,
//! the request one JSON line `{"command": "...", "params": {...}}` of at
//! most 4096 bytes, the reply one JSON line `{"status": "ok", "data": ...}`
//! or `{"status": "error", "message": "..."}`. The socket trusts whoever
//! can open it — group `fips`, as fips's own — and the roles (who may
//! write) are fips-ui's.
//!
//! Also here: the log ring the `log` command reads from, as a tracing
//! layer, and a blocking client for the CLI.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// A request as it arrives.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub command: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    /// A string parameter, or an error naming it.
    pub fn str_param(&self, name: &str) -> Result<&str, Response> {
        self.params
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| Response::error(format!("missing parameter: {name}")))
    }

    /// An optional integer parameter.
    pub fn u64_param(&self, name: &str) -> Option<u64> {
        self.params.get(name).and_then(Value::as_u64)
    }
}

/// A reply, in fips's shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Response {
    Ok { data: Value },
    Error { message: String },
}

impl Response {
    pub fn ok(data: impl Serialize) -> Self {
        match serde_json::to_value(data) {
            Ok(data) => Response::Ok { data },
            Err(e) => Response::error(format!("unserialisable reply: {e}")),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Response::Error {
            message: message.into(),
        }
    }
}

/// The largest request accepted, as fips-ui's client sends at most.
pub const MAX_REQUEST: usize = 4096;

pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// Serve `handler` on the Unix socket at `path` until the task is dropped.
/// A stale socket file is removed first; the file is made group-readable
/// and -writable, and handed to `group` if that group exists and the
/// process is in it (no privilege needed for that). Returns once the
/// socket is bound; the accept loop runs in a spawned task.
#[cfg(unix)]
pub async fn serve(
    path: &Path,
    group: Option<&str>,
    handler: Handler,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(g) = group {
        match group_id(g) {
            Some(gid) => {
                if let Err(e) = std::os::unix::fs::chown(path, None, Some(gid)) {
                    tracing::warn!(socket = %path.display(), group = g, error = %e, "control socket keeps the process's group");
                }
            }
            None => tracing::debug!(
                group = g,
                "no such group; the control socket keeps the process's group"
            ),
        }
    }
    tracing::info!(socket = %path.display(), "control socket listening");
    Ok(tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "control socket accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    handle_connection(stream, handler),
                )
                .await;
            });
        }
    }))
}

#[cfg(unix)]
async fn handle_connection(stream: tokio::net::UnixStream, handler: Handler) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let (r, mut w) = stream.into_split();
    let mut line = String::new();
    let mut reader = BufReader::new(r.take(MAX_REQUEST as u64 + 1));
    let response = match reader.read_line(&mut line).await {
        Ok(0) => Response::error("empty request"),
        Ok(n) if n > MAX_REQUEST => Response::error("request too large"),
        Ok(_) => match serde_json::from_str::<Request>(line.trim_end()) {
            Ok(req) => handler(req).await,
            Err(e) => Response::error(format!("malformed request: {e}")),
        },
        Err(e) => Response::error(format!("read failed: {e}")),
    };
    let mut out = serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"status":"error","message":"unserialisable reply"}"#.to_string());
    out.push('\n');
    let _ = w.write_all(out.as_bytes()).await;
    let _ = w.shutdown().await;
}

/// The gid of a group by name, from /etc/group.
#[cfg(unix)]
fn group_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
    })
}

/// One request to a control socket, blocking, as `fipsctl` does it: for
/// the CLI and for tests.
#[cfg(unix)]
pub fn query(path: &Path, command: &str, params: Value) -> Result<Value, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path)
        .map_err(|e| format!("cannot connect to {}: {e}", path.display()))?;
    let t = Some(std::time::Duration::from_secs(10));
    let _ = stream.set_read_timeout(t);
    let _ = stream.set_write_timeout(t);
    let mut body = serde_json::json!({ "command": command });
    if !params.is_null() {
        body["params"] = params;
    }
    let line = format!("{body}\n");
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("send failed: {e}"))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut reply = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply)
        .map_err(|e| format!("read failed: {e}"))?;
    let response: Response =
        serde_json::from_str(reply.trim_end()).map_err(|e| format!("malformed reply: {e}"))?;
    match response {
        Response::Ok { data } => Ok(data),
        Response::Error { message } => Err(message),
    }
}

/// Not on this platform: Windows has no Unix sockets (a TCP port on
/// loopback, as fips uses there, is a later milestone with the daemon's
/// Windows backend). The daemon and the server log the error and run
/// without a control socket.
#[cfg(not(unix))]
pub async fn serve(
    path: &Path,
    _group: Option<&str>,
    _handler: Handler,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("{}: control sockets need a Unix platform", path.display()),
    ))
}

#[cfg(not(unix))]
pub fn query(path: &Path, _command: &str, _params: Value) -> Result<Value, String> {
    Err(format!(
        "{}: control sockets need a Unix platform",
        path.display()
    ))
}

/// The last lines of the process's log, for the `log` command. A tracing
/// layer feeds it; `lines(n)` reads the newest `n`, oldest first.
#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<std::collections::VecDeque<String>>>,
    capacity: usize,
}

impl LogRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(
                capacity,
            ))),
            capacity,
        }
    }

    pub fn push(&self, line: String) {
        let mut g = self.inner.lock().unwrap();
        if g.len() == self.capacity {
            g.pop_front();
        }
        g.push_back(line);
    }

    pub fn lines(&self, n: usize) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        g.iter().rev().take(n).rev().cloned().collect()
    }

    /// The tracing layer that fills this ring: one line per event, the
    /// time, level, target and fields as `fmt` would print them, no colour.
    pub fn layer<S>(&self) -> impl tracing_subscriber::Layer<S>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        RingLayer { ring: self.clone() }
    }
}

struct RingLayer {
    ring: LogRing,
}

impl<S> tracing_subscriber::Layer<S> for RingLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = FieldLine::default();
        event.record(&mut fields);
        let meta = event.metadata();
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.ring.push(format!(
            "{secs} {:>5} {}: {}",
            meta.level(),
            meta.target(),
            fields.0.trim_end()
        ));
    }
}

#[derive(Default)]
struct FieldLine(String);

impl tracing::field::Visit for FieldLine {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.insert_str(0, &format!("{value:?} "));
        } else {
            self.0.push_str(&format!("{}={value:?} ", field.name()));
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.insert_str(0, &format!("{value} "));
        } else {
            self.0.push_str(&format!("{}={value} ", field.name()));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_gets_its_reply_and_bad_ones_an_error() {
        let dir = std::env::temp_dir().join(format!("pubdom-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");
        let handler: Handler = Arc::new(|req: Request| {
            Box::pin(async move {
                match req.command.as_str() {
                    "echo" => Response::ok(req.params),
                    "name" => match req.str_param("domain") {
                        Ok(d) => Response::ok(d.to_uppercase()),
                        Err(e) => e,
                    },
                    other => Response::error(format!("unknown command: {other}")),
                }
            })
        });
        let _task = serve(&sock, Some("nonexistent-group"), handler)
            .await
            .unwrap();
        let s = sock.clone();
        let out = tokio::task::spawn_blocking(move || {
            (
                query(&s, "echo", serde_json::json!({"a": 1})),
                query(&s, "name", serde_json::json!({"domain": "example.org"})),
                query(&s, "name", Value::Null),
                query(&s, "nope", Value::Null),
            )
        })
        .await
        .unwrap();
        assert_eq!(out.0, Ok(serde_json::json!({"a": 1})));
        assert_eq!(out.1, Ok(Value::String("EXAMPLE.ORG".into())));
        assert_eq!(out.2, Err("missing parameter: domain".into()));
        assert_eq!(out.3, Err("unknown command: nope".into()));
        // A stale socket file is replaced at the next bind.
        drop(_task);
        let again = serve(
            &sock,
            None,
            Arc::new(|_| Box::pin(async { Response::ok(1) })),
        )
        .await;
        assert!(again.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_log_ring_keeps_the_newest_lines() {
        let ring = LogRing::new(3);
        for i in 0..5 {
            ring.push(format!("line {i}"));
        }
        assert_eq!(ring.lines(10), vec!["line 2", "line 3", "line 4"]);
        assert_eq!(ring.lines(1), vec!["line 4"]);
    }
}
