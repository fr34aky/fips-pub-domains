//! The legacy DNS verifier (spec §4, §5.1): `_fips-dns.<domain> TXT` asked
//! of each configured upstream separately, so that agreement can be counted.
//!
//! Strength of the result:
//! - `Dnssec` when hickory validated the RRset itself (`validate = true`,
//!   `Proof::Secure`), from any one upstream;
//! - `Dns` when two or more upstreams returned the same set of npubs;
//! - `DnsSingle` when only one upstream was available or answered.
//!
//! Upstreams that disagree: once any answer validated, only validated
//! answers count — an unvalidated one contradicting a signed zone is forged
//! or stale — and a validated denial is one more group; the largest group
//! wins. Without validated answers the largest group of records wins, and
//! records outrank denials (a stale negative cache must not hide a fresh
//! record). A tie is `Disputed`: list order must never pick between an
//! honest and a poisoned resolver. An answer that failed validation (bogus)
//! counts like a failed upstream: hickory cannot tell tampering from a lost
//! sub-query or a DNSSEC-stripping router, and an attacker able to forge an
//! answer can drop it anyway.
//!
//! A miss is a miss only if every upstream that answered said so; an
//! upstream that failed (timeout, SERVFAIL) is simply not counted, and if
//! none answered the lookup is `Unreachable` — the offline path.

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NoRecords;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::DnssecSummary;
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::rr::Record;
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
        combine(&answers)
    }

    async fn one(r: &TokioResolver, name: &str) -> One {
        Self::classify(name, r.lookup(name, RecordType::TXT).await)
    }

    /// One upstream's result as evidence. An answer that failed DNSSEC
    /// validation counts like no answer: it is not evidence of tampering —
    /// hickory also reports a lost sub-query or a DNSSEC-stripping router as
    /// bogus — and treating it as more would give an attacker nothing, since
    /// one who can forge an answer can also drop it.
    fn classify(name: &str, result: Result<Lookup, NetError>) -> One {
        match result {
            Ok(lookup) => {
                // Judged over the whole answer, CNAME chain included: an
                // insecure CNAME from an unsigned domain to a signed name
                // must not lend that name's validation to the domain.
                let summary = DnssecSummary::from_records(lookup.answers().iter());
                if summary == DnssecSummary::Bogus {
                    tracing::debug!(%name, "TXT answer failed DNSSEC validation");
                    return One::Failed;
                }
                let secure = summary == DnssecSummary::Secure;
                let mut records = Vec::new();
                let mut ttl = u32::MAX;
                for rec in lookup.answers() {
                    if let RData::TXT(txt) = &rec.data
                        && let Some(parsed) = TxtRecord::parse(&txt.to_string())
                    {
                        records.push(parsed);
                        ttl = ttl.min(rec.ttl);
                    }
                }
                if records.is_empty() {
                    // TXT records exist, none is ours: same as no record.
                    One::Miss { secure }
                } else {
                    One::Hit {
                        records,
                        secure,
                        ttl,
                    }
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(nr))) => Self::classify_denial(name, &nr),
            // Not bogus, but hickory could not validate the NSEC3 (more
            // iterations than it accepts — insecure by RFC 9276). Without
            // answers it is an unvalidated denial; with answers (a wildcard
            // expansion) it is not a denial, and counts as no answer.
            Err(NetError::Dns(DnsError::Nsec {
                proof, response, ..
            })) if proof != Proof::Bogus => {
                if response.answers.is_empty() {
                    One::Miss { secure: false }
                } else {
                    One::Failed
                }
            }
            Err(NetError::Dns(DnsError::DnssecBogus))
            | Err(NetError::Dns(DnsError::Nsec {
                proof: Proof::Bogus,
                ..
            })) => {
                tracing::debug!(%name, "TXT answer failed DNSSEC validation");
                One::Failed
            }
            Err(e) => {
                tracing::debug!(%name, error = %e, "TXT upstream failed");
                One::Failed
            }
        }
    }

    /// A denial is validated only when it is for the name asked (not the
    /// target of a CNAME hop), nothing in its authority section failed
    /// validation, and a validated NSEC/NSEC3 without opt-out proves it: a
    /// validated SOA alone comes with an unsigned child of a signed TLD, and
    /// an opt-out NSEC3 of the TLD covers unsigned children too — replayed,
    /// either would fake a validated denial for an unsigned domain.
    fn classify_denial(name: &str, nr: &NoRecords) -> One {
        let auth: &[Record] = nr.authorities.as_deref().unwrap_or(&[]);
        let soa_bogus = nr.soa.as_ref().is_some_and(|s| s.proof == Proof::Bogus);
        if soa_bogus || DnssecSummary::from_records(auth.iter()) == DnssecSummary::Bogus {
            tracing::debug!(%name, "TXT denial failed DNSSEC validation");
            return One::Failed;
        }
        let asked = nr
            .query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(name.trim_end_matches('.'));
        let proven = auth.iter().any(|r| {
            r.proof == Proof::Secure
                && match &r.data {
                    RData::DNSSEC(DNSSECRData::NSEC(_)) => true,
                    RData::DNSSEC(DNSSECRData::NSEC3(n)) => !n.opt_out(),
                    _ => false,
                }
        });
        let opt_out = auth
            .iter()
            .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC3(n)) if n.opt_out()));
        One::Miss {
            secure: asked && proven && !opt_out,
        }
    }
}

fn combine(answers: &[One]) -> (TxtLookup, Option<u32>) {
    let secure = |a: &&One| {
        matches!(
            a,
            One::Hit { secure: true, .. } | One::Miss { secure: true }
        )
    };
    let answered: Vec<&One> = answers
        .iter()
        .filter(|a| !matches!(a, One::Failed))
        .collect();
    if answered.is_empty() {
        return (TxtLookup::Unreachable, None);
    }
    // Once anything validated, only validated answers count: an
    // unvalidated one that contradicts a signed zone is forged or stale.
    // Deliberately so for a validated denial against unvalidated records
    // too: at worst a replayed signed denial unpins the domain until the
    // next validated lookup pins it again, whereas letting forged records
    // outvote it could keep a retired key in use.
    let validated = answered.iter().any(secure);
    let counted: Vec<&One> = if validated {
        answered.into_iter().filter(secure).collect()
    } else {
        answered
    };
    // Group the records by their set of npubs.
    struct Group<'a> {
        key: Vec<Npub>,
        records: &'a Vec<TxtRecord>,
        count: usize,
        /// The shortest, so list order decides nothing.
        ttl: u32,
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut misses = 0;
    for a in &counted {
        match a {
            One::Hit { records, ttl, .. } => {
                let mut key: Vec<Npub> = records.iter().map(|r| r.npub).collect();
                key.sort();
                key.dedup();
                match groups.iter_mut().find(|g| g.key == key) {
                    Some(g) => {
                        g.count += 1;
                        g.ttl = g.ttl.min(*ttl);
                    }
                    None => groups.push(Group {
                        key,
                        records,
                        count: 1,
                        ttl: *ttl,
                    }),
                }
            }
            One::Miss { .. } => misses += 1,
            One::Failed => {}
        }
    }
    let top = groups.iter().map(|g| g.count).max().unwrap_or(0);
    let tied: Vec<&Group> = groups.iter().filter(|g| g.count == top).collect();
    // Validated, a denial is one more group: a replayed signed record must
    // not outvote the zone's signed denials. Unvalidated, records outrank
    // denials — a stale negative cache must not hide a fresh record.
    let denial_wins = if validated {
        misses > top
    } else {
        groups.is_empty()
    };
    if denial_wins {
        let method = if validated {
            Method::Dnssec
        } else if misses >= 2 {
            Method::Dns
        } else {
            Method::DnsSingle
        };
        return (TxtLookup::Miss { method }, None);
    }
    let [best] = tied.as_slice() else {
        return (TxtLookup::Disputed, None);
    };
    if validated && misses == top {
        return (TxtLookup::Disputed, None);
    }
    let method = if validated {
        Method::Dnssec
    } else if best.count >= 2 {
        Method::Dns
    } else {
        Method::DnsSingle
    };
    (
        TxtLookup::Hit {
            records: best.records.clone(),
            method,
        },
        Some(best.ttl),
    )
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
    fn bogus_answers_count_like_no_answer() {
        use hickory_resolver::proto::dnssec::Nsec3HashAlgorithm;
        use hickory_resolver::proto::dnssec::rdata::{NSEC, NSEC3};
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::Name;
        use hickory_resolver::proto::rr::rdata::{CNAME, SOA, TXT};
        let classify = |r| TxtVerifier::classify("_fips-dns.example.org", r);
        assert!(matches!(
            classify(Err(NetError::Dns(DnsError::DnssecBogus))),
            One::Failed
        ));
        // A bogus record inside Ok (not what hickory 0.26 does, but a cached
        // path might): no answer, never an unvalidated hit.
        let text = format!("v=fips1 npub={}", Npub::from_bytes([1; 32]));
        let mut rec = Record::from_rdata(
            Name::from_ascii("_fips-dns.example.org.").unwrap(),
            60,
            RData::TXT(TXT::new(vec![text])),
        );
        rec.proof = Proof::Bogus;
        let lookup = Lookup::new_with_max_ttl(Query::default(), vec![rec.clone()]);
        assert!(matches!(classify(Ok(lookup)), One::Failed));
        rec.proof = Proof::Secure;
        let lookup = Lookup::new_with_max_ttl(Query::default(), vec![rec.clone()]);
        assert!(matches!(
            classify(Ok(lookup)),
            One::Hit { secure: true, .. }
        ));
        // A validated record reached through an unvalidated CNAME lends the
        // domain nothing: the whole answer is judged.
        let mut cname = Record::from_rdata(
            Name::from_ascii("_fips-dns.example.org.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("x.signed.example.").unwrap())),
        );
        cname.proof = Proof::Insecure;
        let lookup = Lookup::new_with_max_ttl(Query::default(), vec![cname, rec]);
        assert!(matches!(
            classify(Ok(lookup)),
            One::Hit { secure: false, .. }
        ));
        // A denial is validated only by a validated NSEC/NSEC3 record — a
        // validated SOA alone (a replayed TLD SOA for an unsigned name)
        // proves nothing. A bogus SOA makes it no answer.
        let mut soa = Record::from_rdata(
            Name::root(),
            60,
            SOA::new(Name::root(), Name::root(), 1, 1, 1, 1, 1),
        );
        let mut nsec = Record::from_rdata(
            Name::root(),
            60,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::root(),
                [RecordType::SOA],
            ))),
        );
        let asked = Query::query(
            Name::from_ascii("_fips-dns.example.org.").unwrap(),
            RecordType::TXT,
        );
        let denial = |soa: Option<&Record<SOA>>, auth: Vec<Record>| {
            let mut nr = NoRecords::new(asked.clone(), ResponseCode::NXDomain);
            nr.soa = soa.map(|s| Box::new(s.clone()));
            nr.authorities = (!auth.is_empty()).then(|| auth.into());
            Err(NetError::Dns(DnsError::NoRecordsFound(nr)))
        };
        assert!(matches!(
            classify(denial(None, vec![])),
            One::Miss { secure: false }
        ));
        soa.proof = Proof::Secure;
        assert!(matches!(
            classify(denial(Some(&soa), vec![])),
            One::Miss { secure: false }
        ));
        nsec.proof = Proof::Insecure;
        assert!(matches!(
            classify(denial(Some(&soa), vec![nsec.clone()])),
            One::Miss { secure: false }
        ));
        nsec.proof = Proof::Secure;
        assert!(matches!(
            classify(denial(Some(&soa), vec![nsec.clone()])),
            One::Miss { secure: true }
        ));
        // …but not a denial of another name (the target of a CNAME hop).
        let mut other = NoRecords::new(
            Query::query(
                Name::from_ascii("gone.signed.example.").unwrap(),
                RecordType::TXT,
            ),
            ResponseCode::NXDomain,
        );
        other.authorities = Some(vec![nsec.clone()].into());
        assert!(matches!(
            classify(Err(NetError::Dns(DnsError::NoRecordsFound(other)))),
            One::Miss { secure: false }
        ));
        // A validated NSEC3 with opt-out covers unsigned children: no proof.
        let mut nsec3 = Record::from_rdata(
            Name::root(),
            60,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                true,
                0,
                vec![],
                vec![0; 20],
                [RecordType::NS],
            ))),
        );
        nsec3.proof = Proof::Secure;
        assert!(matches!(
            classify(denial(Some(&soa), vec![nsec.clone(), nsec3])),
            One::Miss { secure: false }
        ));
        soa.proof = Proof::Bogus;
        assert!(matches!(
            classify(denial(Some(&soa), vec![nsec])),
            One::Failed
        ));
    }

    #[test]
    fn combine_counts_agreement() {
        assert_eq!(
            combine(&[One::Failed, One::Failed]).0,
            TxtLookup::Unreachable
        );
        assert_eq!(
            combine(&[One::Miss { secure: false }, One::Failed]).0,
            TxtLookup::Miss {
                method: Method::DnsSingle
            }
        );
        assert_eq!(
            combine(&[One::Miss { secure: false }, One::Miss { secure: false }]).0,
            TxtLookup::Miss {
                method: Method::Dns
            }
        );
        assert_eq!(
            combine(&[One::Miss { secure: true }]).0,
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
        match combine(&[hit(&[1], false), One::Failed]).0 {
            TxtLookup::Hit { method, .. } => assert_eq!(method, Method::DnsSingle),
            other => panic!("{other:?}"),
        }
        match combine(&[
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
        match combine(&[hit(&[1], true)]).0 {
            TxtLookup::Hit { method, .. } => assert_eq!(method, Method::Dnssec),
            other => panic!("{other:?}"),
        }
        // Two resolvers disagree, a third sides with one of them.
        match combine(&[hit(&[1], false), hit(&[2], false), hit(&[2], false)]).0 {
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
            assert_eq!(combine(&order).0, TxtLookup::Disputed);
        }
        // …unless one side validated — which wins even when outnumbered.
        match combine(&[hit(&[1], false), hit(&[1], false), hit(&[2], true)]).0 {
            TxtLookup::Hit { records, method } => {
                assert_eq!(records[0].npub, Npub::from_bytes([2; 32]));
                assert_eq!(method, Method::Dnssec);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            combine(&[hit(&[1], true), hit(&[2], true)]).0,
            TxtLookup::Disputed
        );
        // Several validated answers: the majority among them (a stale but
        // validly signed cache during a rollover).
        match combine(&[hit(&[1], true), hit(&[2], true), hit(&[2], true)]).0 {
            TxtLookup::Hit { records, .. } => {
                assert_eq!(records[0].npub, Npub::from_bytes([2; 32]))
            }
            other => panic!("{other:?}"),
        }
        // A validated denial outranks an unvalidated record: the operator
        // withdrew it, a forged answer must not keep the old key in use.
        assert_eq!(
            combine(&[One::Miss { secure: true }, hit(&[1], false)]).0,
            TxtLookup::Miss {
                method: Method::Dnssec
            }
        );
        // Validated denials outvote a replayed signed record; a tie between
        // them is disputed.
        assert_eq!(
            combine(&[
                hit(&[1], true),
                One::Miss { secure: true },
                One::Miss { secure: true }
            ])
            .0,
            TxtLookup::Miss {
                method: Method::Dnssec
            }
        );
        assert_eq!(
            combine(&[hit(&[1], true), One::Miss { secure: true }]).0,
            TxtLookup::Disputed
        );
        // Unvalidated resolvers do not tip a validated split.
        assert_eq!(
            combine(&[hit(&[1], true), hit(&[2], true), hit(&[1], false)]).0,
            TxtLookup::Disputed
        );
        // The group's shortest TTL, whatever the order.
        let mut long = hit(&[1], false);
        if let One::Hit { ttl, .. } = &mut long {
            *ttl = 86400;
        }
        assert_eq!(combine(&[long, hit(&[1], false)]).1, Some(300));
        match combine(&[hit(&[2], true), hit(&[1], false)]).0 {
            TxtLookup::Hit { records, method } => {
                assert_eq!(records[0].npub, Npub::from_bytes([2; 32]));
                assert_eq!(method, Method::Dnssec);
            }
            other => panic!("{other:?}"),
        }
        // Hits outrank misses even when misses are more numerous: a stale
        // negative cache somewhere must not hide a fresh record.
        assert!(matches!(
            combine(&[
                One::Miss { secure: false },
                One::Miss { secure: false },
                hit(&[1], false)
            ])
            .0,
            TxtLookup::Hit { .. }
        ));
    }
}
