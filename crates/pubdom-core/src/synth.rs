//! DNS wire format for the three conversations of this protocol, on top of
//! `simple-dns` (what fips uses, so the phone adds no second DNS library):
//!
//! - the application's query and the answer synthesized for it (spec §7),
//! - the step 3 query to the domain's server and its reply (spec §6),
//! - the server's side of step 3 (`server_reply`, spec §6.1).

use crate::identity::Npub;
use simple_dns::rdata::{AAAA, CNAME, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_AAAA: u16 = 28;
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
    p.questions.push(Question::new(Name::new(name).ok()?, qtype, QCLASS::CLASS(CLASS::IN), false));
    p.build_bytes_vec().ok()
}

/// What the domain's server said about a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step3Outcome {
    /// `CNAME <npub>.fips.` — served by this node, cache for `ttl`.
    Node { npub: Npub, ttl: u32 },
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
    p.answers.push(ResourceRecord::new(qname, CLASS::IN, ttl, RData::CNAME(CNAME(target.clone()))));
    if q.qtype == QTYPE_AAAA || q.qtype == QTYPE_ANY {
        let address = u128::from(npub.fips_address());
        p.answers.push(ResourceRecord::new(target, CLASS::IN, ttl, RData::AAAA(AAAA { address })));
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
    let rcode = if target.is_some() { RCODE::NoError } else { RCODE::NameError };
    let mut p = reply_for(&q, rcode)?;
    p.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    if let Some(npub) = target {
        let name = Name::new(&q.name).ok()?.into_owned();
        let target_str = npub.fips_name();
        let t = Name::new(&target_str).ok()?.into_owned();
        p.answers.push(ResourceRecord::new(name, CLASS::IN, ttl, RData::CNAME(CNAME(t))));
    }
    p.build_bytes_vec().ok()
}

fn reply_for(q: &Query, rcode: RCODE) -> Option<Packet<'static>> {
    let mut p = Packet::new_reply(q.id);
    if q.recursion_desired {
        p.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    p.set_flags(PacketFlag::RECURSION_AVAILABLE);
    *p.rcode_mut() = rcode;
    let qtype = QTYPE::try_from(q.qtype).unwrap_or(QTYPE::TYPE(TYPE::A));
    p.questions.push(Question::new(Name::new(&q.name).ok()?.into_owned(), qtype, QCLASS::CLASS(CLASS::IN), false));
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
        assert_eq!(q, Query { id: 0x1234, name: "www.example.org".into(), qtype: QTYPE_AAAA, recursion_desired: true });
        assert!(parse_query(&build_answer(&q, npub(), 30).unwrap()).is_none(), "responses are not queries");
    }

    #[test]
    fn aaaa_answer_carries_cname_and_fips_address() {
        let q = parse_query(&build_query(7, "www.example.org", QTYPE_AAAA).unwrap()).unwrap();
        let bytes = build_answer(&q, npub(), 30).unwrap();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.id(), 7);
        assert!(p.has_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(p.answers.len(), 2);
        assert!(matches!(&p.answers[0].rdata, RData::CNAME(CNAME(n)) if n.to_string() == npub().fips_name()));
        match &p.answers[1].rdata {
            RData::AAAA(a) => assert_eq!(std::net::Ipv6Addr::from(a.address), npub().fips_address()),
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
        assert_eq!(parse_step3_reply(&served, 9), Step3Outcome::Node { npub: npub(), ttl: 300 });
        assert!(Packet::parse(&served).unwrap().has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
        let nx = server_reply(&query, None, 300).unwrap();
        assert_eq!(parse_step3_reply(&nx, 9), Step3Outcome::NotOverFips);
        assert!(matches!(parse_step3_reply(&served, 10), Step3Outcome::Error(_)), "id mismatch");
        assert!(matches!(parse_step3_reply(b"garbage", 9), Step3Outcome::Error(_)));
        let mut p = Packet::new_reply(9);
        p.set_flags(PacketFlag::TRUNCATION);
        assert_eq!(parse_step3_reply(&p.build_bytes_vec().unwrap(), 9), Step3Outcome::Truncated);
    }

    #[test]
    fn rcode_reply() {
        let q = parse_query(&build_query(2, "x.ch", QTYPE_A).unwrap()).unwrap();
        let p_bytes = build_rcode(&q, RCODE::ServerFailure).unwrap();
        assert_eq!(Packet::parse(&p_bytes).unwrap().rcode(), RCODE::ServerFailure);
    }
}
