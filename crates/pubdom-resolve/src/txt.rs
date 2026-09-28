//! The legacy DNS verifier (spec §4, §5.1): `_fips-dns.<domain> TXT` asked
//! of each configured upstream separately, so that agreement can be counted.
//!
//! Strength of the result:
//! - `Dnssec` when hickory validated the RRset itself (`validate = true`,
//!   `Proof::Secure`), from any one upstream;
//! - `Dns` when two or more upstreams returned the same set of npubs;
//! - `DnsSingle` when only one upstream was available or answered.
//!
//! A miss is a miss only if every upstream that answered said so; an
//! upstream that failed (timeout, SERVFAIL) is simply not counted, and if
//! none answered the lookup is `Unreachable` — the offline path.

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use pubdom_core::domain::txt_name;
use pubdom_core::policy::TxtLookup;
use pubdom_core::txt::TxtRecord;
use pubdom_core::{Method, Npub};
use std::net::IpAddr;
use std::time::Duration;

pub struct TxtVerifier {
    resolvers: Vec<(IpAddr, TokioResolver)>,
    timeout: Duration,
}

/// One upstream's answer.
#[derive(Debug)]
enum One {
    Hit { records: Vec<TxtRecord>, secure: bool, ttl: u32 },
    Miss,
    Failed,
}

impl TxtVerifier {
    /// `upstreams` empty → the system's resolvers (`/etc/resolv.conf` and
    /// friends). `dnssec` asks hickory to validate; unsigned zones still
    /// resolve, just without the `Dnssec` strength.
    pub fn new(upstreams: &[IpAddr], dnssec: bool, timeout: Duration) -> Result<Self, String> {
        let ips: Vec<IpAddr> = if upstreams.is_empty() {
            let (conf, _) = hickory_resolver::system_conf::read_system_conf().map_err(|e| e.to_string())?;
            let mut ips: Vec<IpAddr> = conf.name_servers().iter().map(|ns| ns.ip).collect();
            ips.dedup();
            if ips.is_empty() {
                return Err("no upstream resolvers configured".into());
            }
            ips
        } else {
            upstreams.to_vec()
        };
        let mut resolvers = Vec::new();
        for ip in ips {
            let conf = ResolverConfig::from_parts(None, Vec::new(), vec![NameServerConfig::udp_and_tcp(ip)]);
            let mut opts = ResolverOpts::default();
            opts.timeout = timeout;
            opts.attempts = 1;
            opts.validate = dnssec;
            opts.cache_size = 0; // the resolver above us keeps its own caches (spec §5.6)
            let r = Resolver::builder_with_config(conf, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()
                .map_err(|e| e.to_string())?;
            resolvers.push((ip, r));
        }
        Ok(Self { resolvers, timeout })
    }

    pub fn upstreams(&self) -> Vec<IpAddr> {
        self.resolvers.iter().map(|(ip, _)| *ip).collect()
    }

    /// Ask every upstream in parallel and combine (module docs). The second
    /// value is the record TTL to cache a hit for, before the §5.6 cap.
    pub async fn lookup(&self, domain: &str) -> (TxtLookup, Option<u32>) {
        let name = format!("{}.", txt_name(domain));
        let futs = self.resolvers.iter().map(|(ip, r)| {
            let name = name.clone();
            async move {
                let one = tokio::time::timeout(self.timeout + Duration::from_millis(200), Self::one(r, &name))
                    .await
                    .unwrap_or(One::Failed);
                tracing::debug!(upstream = %ip, result = ?one, "TXT lookup");
                one
            }
        });
        let answers: Vec<One> = futures::future::join_all(futs).await;
        combine(answers)
    }

    async fn one(r: &TokioResolver, name: &str) -> One {
        match r.lookup(name, RecordType::TXT).await {
            Ok(lookup) => {
                let mut records = Vec::new();
                let mut secure = false;
                let mut ttl = u32::MAX;
                for rec in lookup.answers() {
                    if let RData::TXT(txt) = &rec.data
                        && let Some(parsed) = TxtRecord::parse(&txt.to_string())
                    {
                        records.push(parsed);
                        secure |= rec.proof == Proof::Secure;
                        ttl = ttl.min(rec.ttl);
                    }
                }
                if records.is_empty() {
                    // TXT records exist, none is ours: same as no record.
                    One::Miss
                } else {
                    One::Hit { records, secure, ttl }
                }
            }
            Err(e) if e.is_no_records_found() || e.is_nx_domain() => One::Miss,
            Err(e) => {
                tracing::debug!(error = %e, "TXT upstream failed");
                One::Failed
            }
        }
    }
}

fn combine(answers: Vec<One>) -> (TxtLookup, Option<u32>) {
    let answered = answers.iter().filter(|a| !matches!(a, One::Failed)).count();
    if answered == 0 {
        return (TxtLookup::Unreachable, None);
    }
    // Group hits by their set of npubs; the largest group is the answer.
    let mut groups: Vec<(Vec<Npub>, Vec<&One>)> = Vec::new();
    for a in &answers {
        if let One::Hit { records, .. } = a {
            let mut key: Vec<Npub> = records.iter().map(|r| r.npub).collect();
            key.sort();
            key.dedup();
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, v)) => v.push(a),
                None => groups.push((key, vec![a])),
            }
        }
    }
    let Some((_, best)) = groups.iter().max_by_key(|(_, v)| v.len()) else {
        return (TxtLookup::Miss, None);
    };
    let secure = best.iter().any(|a| matches!(a, One::Hit { secure: true, .. }));
    let method = if secure {
        Method::Dnssec
    } else if best.len() >= 2 {
        Method::Dns
    } else {
        Method::DnsSingle
    };
    let (records, ttl) = match best[0] {
        One::Hit { records, ttl, .. } => (records.clone(), *ttl),
        _ => unreachable!(),
    };
    (TxtLookup::Hit { records, method }, Some(ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(authors: &[u8], secure: bool) -> One {
        One::Hit {
            records: authors.iter().map(|a| TxtRecord { npub: Npub::from_bytes([*a; 32]), port: None }).collect(),
            secure,
            ttl: 300,
        }
    }

    #[test]
    fn combine_counts_agreement() {
        assert_eq!(combine(vec![One::Failed, One::Failed]).0, TxtLookup::Unreachable);
        assert_eq!(combine(vec![One::Miss, One::Failed]).0, TxtLookup::Miss);
        match combine(vec![hit(&[1], false), One::Failed]).0 {
            TxtLookup::Hit { method, .. } => assert_eq!(method, Method::DnsSingle),
            other => panic!("{other:?}"),
        }
        match combine(vec![hit(&[1], false), hit(&[1], false), One::Miss]).0 {
            TxtLookup::Hit { method, records } => {
                assert_eq!(method, Method::Dns);
                assert_eq!(records.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        match combine(vec![hit(&[1], true)]).0 {
            TxtLookup::Hit { method, .. } => assert_eq!(method, Method::Dnssec),
            other => panic!("{other:?}"),
        }
        // Two resolvers disagree, a third sides with one of them.
        match combine(vec![hit(&[1], false), hit(&[2], false), hit(&[2], false)]).0 {
            TxtLookup::Hit { records, method } => {
                assert_eq!(records[0].npub, Npub::from_bytes([2; 32]));
                assert_eq!(method, Method::Dns);
            }
            other => panic!("{other:?}"),
        }
        // Hits outrank misses even when misses are more numerous: a stale
        // negative cache somewhere must not hide a fresh record.
        assert!(matches!(combine(vec![One::Miss, One::Miss, hit(&[1], false)]).0, TxtLookup::Hit { .. }));
    }
}
