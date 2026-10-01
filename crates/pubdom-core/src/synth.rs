//! DNS wire format for the three conversations of this protocol, on top of
//! `simple-dns` (what fips uses, so the phone adds no second DNS library):
//!
//! - the application's query and the answer synthesized for it (spec §7),
//! - the step 3 query to the domain's server and its reply (spec §6),
//! - the server's side of step 3 (`server_reply`, spec §6.1).

use crate::identity::Npub;
use simple_dns::rdata::{AAAA, CNAME, RData};
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SVCB: u16 = 64;
pub const QTYPE_HTTPS: u16 = 65;
pub const QTYPE_ANY: u16 = 255;

/// The one question of a query, as the resolver needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Lowercase, no trailing dot.
    pub name: String,
    pub qtype: u16,
    pub recursion_desired: bool,
}

pub fn parse_query(bytes: &[u8]) -> Option<Query> {
    let p = Packet::parse(bytes).ok()?;
    if p.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    let q = p.questions.first()?;
    Some(Query {
        id: p.id(),
        name: crate::domain::normalize(&q.qname.to_string())?,
        qtype: u16::from(q.qtype),
        recursion_desired: p.has_flags(PacketFlag::RECURSION_DESIRED),
    })
}

/// A minimal query, for step 3 and for asking fips's responder for
/// `<npub>.fips` (identity registration).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut p = Packet::new_query(id);
    p.set_flags(PacketFlag::RECURSION_DESIRED);
    let qtype = QTYPE::try_from(qtype).ok()?;
    p.questions.push(Question::new(
        Name::new(name).ok()?,
        qtype,
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec().ok()
}

/// What the domain's server said about a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step3Outcome {
    /// `CNAME <npub>.fips.` — served by this node, cache for `ttl`.
    Node {
        npub: Npub,
        ttl: u32,
    },
    /// NXDOMAIN or no CNAME: the name is not over fips (legacy).
    NotOverFips,
    /// Truncated answer: retry over TCP (spec §6).
    Truncated,
    Error(String),
}

pub fn parse_step3_reply(bytes: &[u8], expected_id: u16) -> Step3Outcome {
    let p = match Packet::parse(bytes) {
        Ok(p) => p,
        Err(e) => return Step3Outcome::Error(format!("unparseable reply: {e}")),
    };
    if p.id() != expected_id || !p.has_flags(PacketFlag::RESPONSE) {
        return Step3Outcome::Error("reply does not match the query".into());
    }
    if p.has_flags(PacketFlag::TRUNCATION) {
        return Step3Outcome::Truncated;
    }
    match p.rcode() {
        RCODE::NoError => {}
        RCODE::NameError => return Step3Outcome::NotOverFips,
        other => return Step3Outcome::Error(format!("rcode {other:?}")),
    }
    for rr in &p.answers {
        if let RData::CNAME(CNAME(target)) = &rr.rdata
            && let Some(label) = target.to_string().strip_suffix(".fips")
            && let Ok(npub) = Npub::parse(label)
        {
            return Step3Outcome::Node { npub, ttl: rr.ttl };
        }
    }
    Step3Outcome::NotOverFips
}

/// The answer handed to the application for a name served by `npub`:
/// `CNAME <npub>.fips.` plus, for AAAA (or ANY), the node's `fd…` address.
/// A queries get the CNAME only — NODATA at the target — which, with the
/// public AAAA suppressed, is what makes address selection pick the mesh
/// (spec §7).
pub fn build_answer(q: &Query, npub: Npub, ttl: u32) -> Option<Vec<u8>> {
    let mut p = reply_for(q, RCODE::NoError)?;
    let qname = Name::new(&q.name).ok()?.into_owned();
    let target_str = npub.fips_name();
    let target = Name::new(&target_str).ok()?.into_owned();
    p.answers.push(ResourceRecord::new(
        qname,
        CLASS::IN,
        ttl,
        RData::CNAME(CNAME(target.clone())),
    ));
    if q.qtype == QTYPE_AAAA || q.qtype == QTYPE_ANY {
        let address = u128::from(npub.fips_address());
        p.answers.push(ResourceRecord::new(
            target,
            CLASS::IN,
            ttl,
            RData::AAAA(AAAA { address }),
        ));
    }
    p.build_bytes_vec().ok()
}

/// An empty reply with `rcode` — SERVFAIL when offline and nothing can be
/// done, NXDOMAIN when the user asked for refused names to be visible.
pub fn build_rcode(q: &Query, rcode: RCODE) -> Option<Vec<u8>> {
    reply_for(q, rcode)?.build_bytes_vec().ok()
}

/// The domain server's reply (spec §6.1): authoritative `CNAME <npub>.fips.`
/// for a served name, NXDOMAIN otherwise. `qname` is the raw query name.
pub fn server_reply(query: &[u8], target: Option<Npub>, ttl: u32) -> Option<Vec<u8>> {
    let q = parse_query(query)?;
    let rcode = if target.is_some() {
        RCODE::NoError
    } else {
        RCODE::NameError
    };
    let mut p = reply_for(&q, rcode)?;
    p.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    if let Some(npub) = target {
        let name = Name::new(&q.name).ok()?.into_owned();
        let target_str = npub.fips_name();
        let t = Name::new(&target_str).ok()?.into_owned();
        p.answers.push(ResourceRecord::new(
            name,
            CLASS::IN,
            ttl,
            RData::CNAME(CNAME(t)),
        ));
    }
    p.build_bytes_vec().ok()
}

/// `reply` with every record's TTL capped at `max_ttl`: for a legacy answer
/// forwarded because the lookup overran its budget, so the application's
/// resolver drops it about when the lookup has finished and cached. The
/// TTL fields are patched in place — the message is not re-serialized, so
/// its size, name compression and EDNS flags stay exactly the upstream's;
/// the OPT pseudo-record's TTL (extended RCODE, version, DO) is skipped.
/// `None` when the message does not parse — the caller forwards it as it
/// came.
pub fn clamp_ttls(reply: &[u8], max_ttl: u32) -> Option<Vec<u8>> {
    const TYPE_OPT: u16 = 41;
    let count = |at: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*reply.get(at)?, *reply.get(at + 1)?]) as usize)
    };
    let (qd, an, ns, ar) = (count(4)?, count(6)?, count(8)?, count(10)?);
    let mut out = reply.to_vec();
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(reply, pos)? + 4; // QTYPE, QCLASS
    }
    for _ in 0..an + ns + ar {
        pos = skip_name(reply, pos)?;
        let fixed = reply.get(pos..pos + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        if rtype != TYPE_OPT && ttl > max_ttl {
            out[pos + 4..pos + 8].copy_from_slice(&max_ttl.to_be_bytes());
        }
        pos += 10 + rdlen;
    }
    (pos <= reply.len()).then_some(out)
}

/// Offset just past the name at `pos`: labels, or a compression pointer,
/// which ends it. `None` when truncated or not a name.
fn skip_name(m: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *m.get(pos)?;
        match len & 0xc0 {
            0 if len == 0 => return Some(pos + 1),
            0 => pos += 1 + len as usize,
            0xc0 => {
                m.get(pos + 1)?;
                return Some(pos + 2);
            }
            _ => return None,
        }
    }
}

fn reply_for(q: &Query, rcode: RCODE) -> Option<Packet<'static>> {
    let mut p = Packet::new_reply(q.id);
    if q.recursion_desired {
        p.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    p.set_flags(PacketFlag::RECURSION_AVAILABLE);
    *p.rcode_mut() = rcode;
    let qtype = QTYPE::try_from(q.qtype).unwrap_or(QTYPE::TYPE(TYPE::A));
    p.questions.push(Question::new(
        Name::new(&q.name).ok()?.into_owned(),
        qtype,
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npub() -> Npub {
        Npub::from_bytes([3u8; 32])
    }

    #[test]
    fn query_round_trip() {
        let bytes = build_query(0x1234, "WWW.example.org.", QTYPE_AAAA).unwrap();
        let q = parse_query(&bytes).unwrap();
        assert_eq!(
            q,
            Query {
                id: 0x1234,
                name: "www.example.org".into(),
                qtype: QTYPE_AAAA,
                recursion_desired: true
            }
        );
        assert!(
            parse_query(&build_answer(&q, npub(), 30).unwrap()).is_none(),
            "responses are not queries"
        );
    }

    #[test]
    fn aaaa_answer_carries_cname_and_fips_address() {
        let q = parse_query(&build_query(7, "www.example.org", QTYPE_AAAA).unwrap()).unwrap();
        let bytes = build_answer(&q, npub(), 30).unwrap();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.id(), 7);
        assert!(p.has_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(p.answers.len(), 2);
        assert!(
            matches!(&p.answers[0].rdata, RData::CNAME(CNAME(n)) if n.to_string() == npub().fips_name())
        );
        match &p.answers[1].rdata {
            RData::AAAA(a) => {
                assert_eq!(std::net::Ipv6Addr::from(a.address), npub().fips_address())
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(p.answers[1].ttl, 30);
    }

    #[test]
    fn a_answer_is_cname_only() {
        let q = parse_query(&build_query(7, "www.example.org", QTYPE_A).unwrap()).unwrap();
        let p_bytes = build_answer(&q, npub(), 30).unwrap();
        let p = Packet::parse(&p_bytes).unwrap();
        assert_eq!(p.answers.len(), 1);
        assert_eq!(p.rcode(), RCODE::NoError);
    }

    #[test]
    fn step3_reply_parsing() {
        let query = build_query(9, "www.example.org", QTYPE_AAAA).unwrap();
        let served = server_reply(&query, Some(npub()), 300).unwrap();
        assert_eq!(
            parse_step3_reply(&served, 9),
            Step3Outcome::Node {
                npub: npub(),
                ttl: 300
            }
        );
        assert!(
            Packet::parse(&served)
                .unwrap()
                .has_flags(PacketFlag::AUTHORITATIVE_ANSWER)
        );
        let nx = server_reply(&query, None, 300).unwrap();
        assert_eq!(parse_step3_reply(&nx, 9), Step3Outcome::NotOverFips);
        assert!(
            matches!(parse_step3_reply(&served, 10), Step3Outcome::Error(_)),
            "id mismatch"
        );
        assert!(matches!(
            parse_step3_reply(b"garbage", 9),
            Step3Outcome::Error(_)
        ));
        let mut p = Packet::new_reply(9);
        p.set_flags(PacketFlag::TRUNCATION);
        assert_eq!(
            parse_step3_reply(&p.build_bytes_vec().unwrap(), 9),
            Step3Outcome::Truncated
        );
    }

    #[test]
    fn rcode_reply() {
        let q = parse_query(&build_query(2, "x.ch", QTYPE_A).unwrap()).unwrap();
        let p_bytes = build_rcode(&q, RCODE::ServerFailure).unwrap();
        assert_eq!(
            Packet::parse(&p_bytes).unwrap().rcode(),
            RCODE::ServerFailure
        );
    }

    #[test]
    fn clamp_ttls_patches_in_place_and_leaves_opt_alone() {
        let q = parse_query(&build_query(7, "www.example.org", QTYPE_AAAA).unwrap()).unwrap();
        // Compressed, as an upstream builds it, plus an EDNS OPT record
        // whose TTL carries the DO bit, not a lifetime.
        let plain = build_answer(&q, npub(), 300).unwrap();
        let mut p = Packet::parse(&plain).unwrap();
        p.additional_records.push(ResourceRecord::new(
            Name::new_unchecked("."),
            CLASS::IN,
            0,
            RData::A(simple_dns::rdata::A { address: 0 }),
        ));
        let mut long = p.build_bytes_vec_compressed().unwrap();
        // Turn the placeholder into OPT: type 41, class 4096 (UDP size),
        // TTL 0x0000_8000 (DO), rdlength 0.
        let n = long.len();
        long.truncate(n - 4); // drop the A's rdata
        long[n - 4 - 10..n - 4].copy_from_slice(&[0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
        let short = clamp_ttls(&long, 5).unwrap();
        assert_eq!(short.len(), long.len(), "patched, not rebuilt");
        let diffs: Vec<usize> = (0..long.len()).filter(|&i| long[i] != short[i]).collect();
        assert_eq!(diffs.len(), 4, "two bytes per TTL (300 → 5), two records");
        let parsed = Packet::parse(&short).unwrap();
        assert_eq!(parsed.answers.len(), 2);
        assert!(parsed.answers.iter().all(|rr| rr.ttl == 5));
        assert_eq!(
            parsed.opt().map(|o| o.udp_packet_size),
            Some(4096),
            "OPT survives"
        );
        assert_eq!(
            &short[short.len() - 6..],
            &[0, 0, 0x80, 0, 0, 0],
            "OPT TTL untouched"
        );
        // A TTL already below the cap is left alone, bytes equal.
        let brief = build_answer(&q, npub(), 2).unwrap();
        assert_eq!(clamp_ttls(&brief, 5).unwrap(), brief);
        // Garbage and truncation are not answers.
        assert!(clamp_ttls(b"\x00\x07", 5).is_none());
        assert!(clamp_ttls(&long[..long.len() - 3], 5).is_none());
    }
}
