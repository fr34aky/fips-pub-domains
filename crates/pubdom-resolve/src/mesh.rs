//! Step 3 transport (spec §6): a DNS query over the mesh to the domain's
//! server, and the identity registration that makes the answer routable.
//!
//! The trait is blocking. The phone's only way onto the mesh is a userspace
//! TCP/IP stack driven from the calling thread (fips2go `meshhttp.rs`), and
//! DNS is low-rate, so a blocking call per query — run through
//! `spawn_blocking` from async code — is the honest shape.

use pubdom_core::Npub;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
use std::time::Duration;

pub trait MeshDns: Send + Sync {
    /// One DNS exchange over UDP with `server` on the mesh. The reply may be
    /// truncated; the caller then calls [`query_tcp`](Self::query_tcp).
    fn query_udp(&self, server: SocketAddrV6, msg: &[u8], timeout: Duration) -> io::Result<Vec<u8>>;

    /// The same over TCP (RFC 7766 framing), for truncated answers.
    fn query_tcp(&self, server: SocketAddrV6, msg: &[u8], timeout: Duration) -> io::Result<Vec<u8>>;

    /// Make the local fips node able to route to `npub`: ask its own `.fips`
    /// responder for `<npub>.fips` (spec §6). Returns whether the responder
    /// answered with an address — which, for the domain's server, is also the
    /// only reachability signal phase 1 has (spec §7).
    fn register(&self, npub: Npub, timeout: Duration) -> bool;
}

/// Kernel sockets: desktops and servers, where the node's TUN exists and
/// `fd…` destinations route through it.
pub struct KernelMeshDns {
    /// fips's `.fips` responder, `[::1]:5354` by default.
    pub responder: SocketAddr,
    /// Bind mesh queries to this address (the node's own fips address), so
    /// the server sees this node's npub and multi-homed hosts pick the TUN.
    pub bind: Option<Ipv6Addr>,
}

impl KernelMeshDns {
    pub fn new(responder: SocketAddr, bind: Option<Ipv6Addr>) -> Self {
        Self { responder, bind }
    }

    fn udp_socket(&self) -> io::Result<UdpSocket> {
        let bind = self.bind.unwrap_or(Ipv6Addr::UNSPECIFIED);
        UdpSocket::bind(SocketAddrV6::new(bind, 0, 0, 0))
    }
}

impl MeshDns for KernelMeshDns {
    fn query_udp(&self, server: SocketAddrV6, msg: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        let sock = self.udp_socket()?;
        sock.set_read_timeout(Some(timeout))?;
        sock.connect(server)?;
        sock.send(msg)?;
        // The mesh MTU is ~1200; anything larger arrives truncated (spec §6).
        let mut buf = vec![0u8; 1500];
        let n = sock.recv(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn query_tcp(&self, server: SocketAddrV6, msg: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&SocketAddr::V6(server), timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let len = u16::try_from(msg.len()).map_err(|_| io::Error::other("query too long"))?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(msg)?;
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr)?;
        let mut buf = vec![0u8; u16::from_be_bytes(hdr) as usize];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn register(&self, npub: Npub, timeout: Duration) -> bool {
        let Some(query) = pubdom_core::synth::build_query(0x4e50, &npub.fips_name(), pubdom_core::synth::QTYPE_AAAA)
        else {
            return false;
        };
        let attempt = || -> io::Result<bool> {
            let sock = UdpSocket::bind(if self.responder.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
            sock.set_read_timeout(Some(timeout))?;
            sock.connect(self.responder)?;
            sock.send(&query)?;
            let mut buf = [0u8; 512];
            let n = sock.recv(&mut buf)?;
            Ok(matches!(
                pubdom_core::synth::parse_step3_reply(&buf[..n], 0x4e50),
                // The responder answers AAAA, not CNAME; any NoError reply
                // with our id means it resolved and registered the identity.
                pubdom_core::synth::Step3Outcome::NotOverFips | pubdom_core::synth::Step3Outcome::Node { .. }
            ) && simple_dns_noerror(&buf[..n]))
        };
        attempt().unwrap_or(false)
    }
}

fn simple_dns_noerror(bytes: &[u8]) -> bool {
    // Cheap header check: rcode nibble of byte 3 (RFC 1035 §4.1.1).
    bytes.len() >= 12 && bytes[3] & 0x0f == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubdom_core::synth::{QTYPE_AAAA, build_query, parse_query, server_reply};
    use std::net::TcpListener;

    fn npub() -> Npub {
        Npub::from_bytes([5u8; 32])
    }

    #[test]
    fn udp_and_tcp_exchanges_on_loopback() {
        // A stand-in server on loopback; the trait does not care that the
        // address is not fd… — the kernel routes it either way.
        let udp = UdpSocket::bind("[::1]:0").unwrap();
        let tcp = TcpListener::bind("[::1]:0").unwrap();
        let udp_addr = match udp.local_addr().unwrap() {
            SocketAddr::V6(a) => a,
            _ => unreachable!(),
        };
        let tcp_addr = match tcp.local_addr().unwrap() {
            SocketAddr::V6(a) => a,
            _ => unreachable!(),
        };
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            let reply = server_reply(&buf[..n], Some(npub()), 60).unwrap();
            udp.send_to(&reply, from).unwrap();
        });
        std::thread::spawn(move || {
            let (mut s, _) = tcp.accept().unwrap();
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).unwrap();
            let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
            s.read_exact(&mut q).unwrap();
            let reply = server_reply(&q, None, 60).unwrap();
            s.write_all(&(reply.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&reply).unwrap();
        });
        let mesh = KernelMeshDns::new("[::1]:1".parse().unwrap(), None);
        let q = build_query(11, "www.example.org", QTYPE_AAAA).unwrap();
        let r = mesh.query_udp(udp_addr, &q, Duration::from_secs(2)).unwrap();
        assert_eq!(parse_query(&r), None, "it is a reply");
        assert!(matches!(
            pubdom_core::synth::parse_step3_reply(&r, 11),
            pubdom_core::synth::Step3Outcome::Node { .. }
        ));
        let r = mesh.query_tcp(tcp_addr, &q, Duration::from_secs(2)).unwrap();
        assert_eq!(pubdom_core::synth::parse_step3_reply(&r, 11), pubdom_core::synth::Step3Outcome::NotOverFips);
    }

    #[test]
    fn register_reports_false_when_no_responder() {
        let mesh = KernelMeshDns::new("[::1]:9".parse().unwrap(), None);
        assert!(!mesh.register(npub(), Duration::from_millis(200)));
    }
}
