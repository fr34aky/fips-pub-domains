//! The legacy DNS verifier (spec §4, §5.1): `_fips-dns.<domain> TXT` asked
//! of each configured upstream separately, so that agreement can be counted.
//!
//! Strength of the result:
//! - `Dnssec` when hickory validated the RRset itself (`validate = true`,
//!   `Proof::Secure`), from any one upstream;
//! - `Dns` when two or more upstreams returned the same set of npubs;
//! - `DnsSingle` when only one upstream was available or answered.
//!
//! Upstreams naming different npubs: the largest group wins; a tie is no
//! answer (`Unreachable`, so pins decide) unless exactly one side validated
//! under DNSSEC — else list order alone would pick between an honest and a
//! poisoned resolver.
//!
//! A miss is a miss only if every upstream that answered said so; an
//! upstream that failed (timeout, SERVFAIL) is simply not counted, and if
//! none answered the lookup is `Unreachable` — the offline path.

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
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

/// One upstream's answer. `secure` on a miss: the denial (NSEC/NSEC3)
/// validated under DNSSEC.
#[derive(Debug)]
enum One {
    Hit {
        records: Vec<TxtRecord>,
        secure: bool,
        ttl: u32,
    },
    Miss {
        secure: bool,
    },
    Failed,
}

impl TxtVerifier {
    /// `upstreams` empty → the system's resolvers (`/etc/resolv.conf` and
    /// friends). `dnssec` asks hickory to validate; unsigned zones still
    /// resolve, just without the `Dnssec` strength.
    pub fn new(upstreams: &[IpAddr], dnssec: bool, timeout: Duration) -> Result<Self, String> {
        let ips: Vec<IpAddr> = if upstreams.is_empty() {
            let (conf, _) =
                hickory_resolver::system_conf::read_system_conf().map_err(|e| e.to_string())?;
            let ips: Vec<IpAddr> = conf.name_servers().iter().map(|ns| ns.ip).collect();
            if ips.is_empty() {
                return Err("no upstream resolvers configured".into());
            }
            ips
        } else {
            upstreams.to_vec()
        };
        // The same server twice must not count as two agreeing resolvers.
        let ips = unique(ips);
        let mut resolvers = Vec::new();
        for ip in ips {
            let conf = ResolverConfig::from_parts(
                None,
                Vec::new(),
                vec![NameServerConfig::udp_and_tcp(ip)],
            );
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
                let one = tokio::time::timeout(
                    self.timeout + Duration::from_millis(200),
                    Self::one(r, &name),
                )
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
                    // TXT records exist, none is ours: same as no record. The
                    // records themselves may be validated even so.
                    let secure = lookup.answers().iter().any(|r| r.proof == Proof::Secure);
                    One::Miss { secure }
                } else {
                    One::Hit {
                        records,
                        secure,
                        ttl,
                    }
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(nr))) => {
                // A validated SOA in the authority section means the denial
                // itself was proven (NSEC/NSEC3 checked by the validator).
                let secure = nr
                    .soa
                    .as_ref()
                    .is_some_and(|soa| soa.proof == Proof::Secure);
                One::Miss { secure }
            }
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
    let top = groups.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
    let tied: Vec<&(Vec<Npub>, Vec<&One>)> =
        groups.iter().filter(|(_, v)| v.len() == top).collect();
    let is_secure = |v: &Vec<&One>| v.iter().any(|a| matches!(a, One::Hit { secure: true, .. }));
    let best = match tied.as_slice() {
        [] => None,
        [one] => Some(*one),
        many => {
            let secure: Vec<_> = many.iter().filter(|(_, v)| is_secure(v)).collect();
            if let [one] = secure.as_slice() {
                Some(**one)
            } else {
                tracing::warn!("upstream resolvers disagree on the _fips-dns record; not using it");
                return (TxtLookup::Unreachable, None);
            }
        }
    };
    let Some((_, best)) = best else {
        let misses = answers
            .iter()
            .filter(|a| matches!(a, One::Miss { .. }))
            .count();
        let secure = answers
            .iter()
            .any(|a| matches!(a, One::Miss { secure: true }));
        let method = if secure {
            Method::Dnssec
        } else if misses >= 2 {
            Method::Dns
        } else {
            Method::DnsSingle
        };
        return (TxtLookup::Miss { method }, None);
    };
    let secure = best
        .iter()
        .any(|a| matches!(a, One::Hit { secure: true, .. }));
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

/// Order-preserving dedup (a resolver listed twice is one resolver).
fn unique(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::with_capacity(ips.len());
    for ip in ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(authors: &[u8], secure: bool) -> One {
        One::Hit {
            records: authors
                .iter()
                .map(|a| TxtRecord {
                    npub: Npub::from_bytes([*a; 32]),
                    port: None,
                })
                .collect(),
            secure,
            ttl: 300,
        }
    }

    #[test]
    fn combine_counts_agreement() {
        assert_eq!(
            combine(vec![One::Failed, One::Failed]).0,
            TxtLookup::Unreachable
        );
        assert_eq!(
            combine(vec![One::Miss { secure: false }, One::Failed]).0,
            TxtLookup::Miss {
                method: Method::DnsSingle
            }
        );
        assert_eq!(
            combine(vec![
                One::Miss { secure: false },
                One::Miss { secure: false }
            ])
            .0,
            TxtLookup::Miss {
                method: Method::Dns
            }
        );
        assert_eq!(
            combine(vec![One::Miss { secure: true }]).0,
            TxtLookup::Miss {
                method: Method::Dnssec
            }
        );
        assert_eq!(
            unique(vec![
                "1.1.1.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "1.1.1.1".parse().unwrap()
            ])
            .len(),
            2
        );
        match combine(vec![hit(&[1], false), One::Failed]).0 {
            TxtLookup::Hit { method, .. } => assert_eq!(method, Method::DnsSingle),
            other => panic!("{other:?}"),
        }
        match combine(vec![
            hit(&[1], false),
            hit(&[1], false),
            One::Miss { secure: false },
        ])
        .0
        {
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
        // A tie between different answers is no answer, whatever the order…
        for order in [
            vec![hit(&[1], false), hit(&[2], false)],
            vec![hit(&[2], false), hit(&[1], false)],
        ] {
            assert_eq!(combine(order).0, TxtLookup::Unreachable);
        }
        // …unless one side validated.
        match combine(vec![hit(&[2], true), hit(&[1], false)]).0 {
            TxtLookup::Hit { records, method } => {
                assert_eq!(records[0].npub, Npub::from_bytes([2; 32]));
                assert_eq!(method, Method::Dnssec);
            }
            other => panic!("{other:?}"),
        }
        // Hits outrank misses even when misses are more numerous: a stale
        // negative cache somewhere must not hide a fresh record.
        assert!(matches!(
            combine(vec![
                One::Miss { secure: false },
                One::Miss { secure: false },
                hit(&[1], false)
            ])
            .0,
            TxtLookup::Hit { .. }
        ));
    }
}
