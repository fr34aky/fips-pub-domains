//! Legacy passthrough: the query, byte for byte, to the upstream resolvers
//! in order, UDP first and TCP when the answer comes back truncated. This
//! is what every name that is not over fips goes through, so it must be
//! boring and never clever.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

pub async fn forward(query: &[u8], upstreams: &[IpAddr]) -> Option<Vec<u8>> {
    let addrs: Vec<SocketAddr> = upstreams.iter().map(|ip| SocketAddr::new(*ip, 53)).collect();
    forward_to(query, &addrs).await
}

/// The same, to explicit socket addresses (fips's `.fips` responder).
pub async fn forward_to(query: &[u8], servers: &[SocketAddr]) -> Option<Vec<u8>> {
    for addr in servers {
        let ip = addr.ip();
        match tokio::time::timeout(UPSTREAM_TIMEOUT, udp(query, *addr)).await {
            Ok(Ok(reply)) => {
                if reply.len() >= 3 && reply[2] & 0x02 != 0 {
                    // TC bit: the upstream has more than fits in UDP.
                    if let Ok(Ok(full)) = tokio::time::timeout(UPSTREAM_TIMEOUT * 2, tcp(query, *addr)).await {
                        return Some(full);
                    }
                }
                return Some(reply);
            }
            Ok(Err(e)) => tracing::debug!(upstream = %ip, error = %e, "upstream failed"),
            Err(_) => tracing::debug!(upstream = %ip, "upstream timed out"),
        }
    }
    None
}

/// Is this a `.fips` name — fips's own namespace, answered by its responder?
pub fn is_fips_name(query: &[u8]) -> bool {
    pubdom_core::synth::parse_query(query)
        .is_some_and(|q| q.name == "fips" || q.name.ends_with(".fips"))
}

async fn udp(query: &[u8], addr: SocketAddr) -> std::io::Result<Vec<u8>> {
    let sock = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
    sock.connect(addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        // Match the transaction id; anything else is a stray datagram.
        if n >= 2 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn tcp(query: &[u8], addr: SocketAddr) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(&(query.len() as u16).to_be_bytes()).await?;
    s.write_all(query).await?;
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    let mut buf = vec![0u8; u16::from_be_bytes(hdr) as usize];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// SERVFAIL for `query`, when nothing upstream answered.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let q = pubdom_core::synth::parse_query(query)?;
    pubdom_core::synth::build_rcode(&q, simple_dns::RCODE::ServerFailure)
}
