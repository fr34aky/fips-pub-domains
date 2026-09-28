//! DNSSEC proofs carried in claims (spec §3.1 `dnssec` tag, §5.5): the
//! `_fips-dns` TXT RRset and every record needed to validate it from the DNS
//! root, so a node that cannot reach DNS can still verify a domain it has
//! never seen.
//!
//! The chain is RFC 9102 style: resource records in uncompressed wire
//! format, one after the other, base64-encoded. Order does not matter. It
//! holds, for the zone `Z` that signs the TXT record and each zone above it
//! up to the root: `Z`'s DNSKEY RRset with its RRSIGs, and (except for the
//! root) `Z`'s DS RRset with the RRSIGs its parent made.
//!
//! Validation is plain RFC 4035 without a resolver:
//! - the root DNSKEY RRset is signed by a key in the built-in trust anchors
//!   (both root KSKs, 2017 and 2024);
//! - a child's DNSKEY RRset is signed by a key a validated DS RRset covers;
//! - every RRSIG must be current (inception ≤ now ≤ expiration) and made by
//!   the zone owning the name, not a wildcard expansion.
//!
//! [`build_chain`] asks a recursive resolver with the DO bit and follows the
//! RRSIGs' signer names up to the root.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hickory_resolver::proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, RRSIG};
use hickory_resolver::proto::dnssec::{TrustAnchors, Verifier};
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder, NameEncoding,
};
use pubdom_core::claim::Claim;
use pubdom_core::domain::txt_name;
use pubdom_core::policy::ProofVerifier;
use pubdom_core::txt::TxtRecord;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// Longest chain accepted: a TXT record a few zones deep is well under
/// 10 KB even with RSA keys; nothing legitimate comes near this.
const MAX_CHAIN_BYTES: usize = 64 * 1024;
/// Zones walked from the TXT record to the root; bounds a malicious chain.
const MAX_DEPTH: usize = 16;

/// Why a proof did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    Encoding(String),
    /// No validated TXT RRset at `_fips-dns.<domain>`.
    Unsigned(String),
    /// Validated, but no record names the claim's author.
    NotNamed,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::Encoding(e) => write!(f, "malformed chain: {e}"),
            ProofError::Unsigned(e) => write!(f, "does not validate: {e}"),
            ProofError::NotNamed => write!(f, "validates, but does not name the author"),
        }
    }
}

/// What a valid proof shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proven {
    pub records: Vec<TxtRecord>,
    /// The earliest RRSIG expiration in the chain (unix seconds): the proof
    /// is worthless after it, and the server must re-publish before.
    pub expires: u64,
}

/// Encode records as a chain.
pub fn encode_chain(records: &[Record]) -> Result<String, String> {
    let mut buf = Vec::new();
    {
        let mut enc = BinEncoder::new(&mut buf);
        enc.set_name_encoding(NameEncoding::Uncompressed);
        for r in records {
            r.emit(&mut enc).map_err(|e| e.to_string())?;
        }
    }
    Ok(B64.encode(buf))
}

fn decode_chain(chain: &str) -> Result<Vec<Record>, ProofError> {
    let bytes = B64
        .decode(chain.trim())
        .map_err(|e| ProofError::Encoding(e.to_string()))?;
    if bytes.len() > MAX_CHAIN_BYTES {
        return Err(ProofError::Encoding("too long".into()));
    }
    let mut dec = BinDecoder::new(&bytes);
    let mut out = Vec::new();
    while !dec.is_empty() {
        let r = Record::read(&mut dec).map_err(|e| ProofError::Encoding(e.to_string()))?;
        out.push(r);
    }
    Ok(out)
}

/// Verify `chain` as a proof that `_fips-dns.<domain>` exists and is
/// DNSSEC-valid at `now` against `anchors`.
pub fn verify_chain(
    chain: &str,
    domain: &str,
    now: u64,
    anchors: &TrustAnchors,
) -> Result<Proven, ProofError> {
    let records = decode_chain(chain)?;
    let owner = Name::from_str(&format!("{}.", txt_name(domain)))
        .map_err(|e| ProofError::Encoding(e.to_string()))?;
    let v = Validator {
        records: &records,
        now,
        anchors,
    };
    let mut expires = u64::MAX;
    v.rrset(&owner, RecordType::TXT, &mut expires, 0)
        .map_err(ProofError::Unsigned)?;
    let mut out = Vec::new();
    for r in v.set(&owner, RecordType::TXT) {
        if let RData::TXT(t) = &r.data {
            let text: String = t
                .txt_data
                .iter()
                .map(|s| String::from_utf8_lossy(s))
                .collect();
            if let Some(rec) = TxtRecord::parse(&text) {
                out.push(rec);
            }
        }
    }
    Ok(Proven {
        records: out,
        expires,
    })
}

struct Validator<'a> {
    records: &'a [Record],
    now: u64,
    anchors: &'a TrustAnchors,
}

impl Validator<'_> {
    /// The RRset (name, type), without signatures.
    fn set(&self, name: &Name, ty: RecordType) -> Vec<&Record> {
        self.records
            .iter()
            .filter(|r| r.record_type() == ty && (&r.name) == name && r.dns_class == DNSClass::IN)
            .collect()
    }

    fn sigs(&self, name: &Name, ty: RecordType) -> Vec<&RRSIG> {
        self.records
            .iter()
            .filter(|r| (&r.name) == name && r.dns_class == DNSClass::IN)
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == ty => Some(s),
                _ => None,
            })
            .collect()
    }

    fn keys(&self, zone: &Name) -> Vec<&DNSKEY> {
        self.set(zone, RecordType::DNSKEY)
            .into_iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(k)) if k.zone_key() && !k.revoke() => Some(k),
                _ => None,
            })
            .collect()
    }

    /// Validate the RRset (name, ty): some current RRSIG over it by a key of
    /// its zone whose DNSKEY RRset validates in turn. Lowers `expires` to the
    /// signatures relied on.
    fn rrset(
        &self,
        name: &Name,
        ty: RecordType,
        expires: &mut u64,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("chain too deep".into());
        }
        let set = self.set(name, ty);
        if set.is_empty() {
            return Err(format!("no {ty} at {name}"));
        }
        let mut why = format!("no RRSIG over {name} {ty}");
        for sig in self.sigs(name, ty) {
            let input = sig.input();
            let signer = &input.signer_name;
            // The signer is the zone owning the name: an ancestor (or the
            // name itself); a DS record is signed by the parent, never by
            // the zone it describes; a DNSKEY RRset only by its own zone.
            if !signer.zone_of(name)
                || (ty == RecordType::DS && signer == name)
                || (ty == RecordType::DNSKEY && signer != name)
            {
                why = format!("{name} {ty}: signer {signer} is not its zone");
                continue;
            }
            // Wildcard expansions would need a proof of non-existence of
            // the name itself; not supported.
            if input.num_labels != name.num_labels() {
                why = format!("{name} {ty}: wildcard expansion");
                continue;
            }
            let (inception, expiration) = (
                u64::from(input.sig_inception.get()),
                u64::from(input.sig_expiration.get()),
            );
            if self.now < inception || self.now > expiration {
                why = format!(
                    "{name} {ty}: signature not valid now (valid {inception}..{expiration})"
                );
                continue;
            }
            let mut exp = (*expires).min(expiration);
            let trusted_keys: Vec<&DNSKEY> = if ty == RecordType::DNSKEY {
                // The zone's own key set, self-signed: the signing key must be
                // anchored (root) or covered by a validated DS.
                match self.anchored_keys(name, &mut exp, depth) {
                    Ok(k) => k,
                    Err(e) => {
                        why = e;
                        continue;
                    }
                }
            } else {
                if let Err(e) = self.rrset(signer, RecordType::DNSKEY, &mut exp, depth + 1) {
                    why = e;
                    continue;
                }
                self.keys(signer)
            };
            let ok = trusted_keys.iter().any(|k| {
                k.algorithm() == input.algorithm
                    && k.calculate_key_tag().ok() == Some(input.key_tag)
                    && k.verify_rrsig(name, DNSClass::IN, sig, set.iter().copied())
                        .is_ok()
            });
            if ok {
                *expires = exp;
                return Ok(());
            }
            why = format!("{name} {ty}: signature does not verify");
        }
        Err(why)
    }

    /// The keys of `zone` that are trust points: in the anchors (root), or
    /// covered by a validated DS RRset from the parent.
    fn anchored_keys(
        &self,
        zone: &Name,
        expires: &mut u64,
        depth: usize,
    ) -> Result<Vec<&DNSKEY>, String> {
        let keys = self.keys(zone);
        if zone.is_root() {
            let k: Vec<&DNSKEY> = keys
                .into_iter()
                .filter(|k| self.anchors.contains(k.public_key()))
                .collect();
            return if k.is_empty() {
                Err("root DNSKEY RRset holds no trust anchor".into())
            } else {
                Ok(k)
            };
        }
        self.rrset(zone, RecordType::DS, expires, depth + 1)?;
        let ds: Vec<&DS> = self
            .set(zone, RecordType::DS)
            .into_iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DS(d)) => Some(d),
                _ => None,
            })
            .collect();
        let k: Vec<&DNSKEY> = keys
            .into_iter()
            .filter(|k| ds.iter().any(|d| d.covers(zone, k).unwrap_or(false)))
            .collect();
        if k.is_empty() {
            Err(format!("no DNSKEY of {zone} matches its DS"))
        } else {
            Ok(k)
        }
    }
}

/// The resolver's [`ProofVerifier`]: the built-in root trust anchors and the
/// claim's `dnssec` tag.
#[derive(Default)]
pub struct DnssecProofs {
    anchors: TrustAnchors,
}

impl DnssecProofs {
    pub fn check(&self, claim: &Claim, now: u64) -> Result<Proven, ProofError> {
        let chain = claim
            .dnssec
            .as_deref()
            .ok_or_else(|| ProofError::Unsigned("the claim carries no proof".into()))?;
        let proven = verify_chain(chain, &claim.domain, now, &self.anchors)?;
        if proven.records.iter().any(|r| r.npub == claim.author) {
            Ok(proven)
        } else {
            Err(ProofError::NotNamed)
        }
    }
}

impl ProofVerifier for DnssecProofs {
    fn verify(&self, claim: &Claim, now: u64) -> bool {
        match self.check(claim, now) {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!(domain = %claim.domain, author = %claim.author, error = %e, "claim's DNSSEC proof rejected");
                false
            }
        }
    }
}

/// Collect the chain for `_fips-dns.<domain>` from `upstream`, a recursive
/// resolver that returns DNSSEC records when asked with the DO bit (most
/// public ones do; a stub that strips them yields "no RRSIG").
pub async fn build_chain(
    domain: &str,
    upstream: IpAddr,
    timeout: Duration,
) -> Result<String, String> {
    let owner = Name::from_str(&format!("{}.", txt_name(domain))).map_err(|e| e.to_string())?;
    let mut out: Vec<Record> = Vec::new();
    // The TXT RRset; its RRSIG's signer is the zone to walk up from.
    let txt = ask(upstream, &owner, RecordType::TXT, timeout).await?;
    let mut zone = signer_of(&txt, &owner, RecordType::TXT)
        .ok_or_else(|| format!("{owner} TXT is not signed (is the zone DNSSEC-signed?)"))?;
    out.extend(txt);
    for _ in 0..MAX_DEPTH {
        out.extend(ask(upstream, &zone, RecordType::DNSKEY, timeout).await?);
        if zone.is_root() {
            let chain = encode_chain(&out)?;
            if chain.len() > pubdom_core::claim::MAX_DNSSEC_B64 {
                // Clients drop a longer tag; better no proof than a claim
                // that silently loses it.
                return Err(format!(
                    "chain of {} bytes is too long for a claim",
                    chain.len()
                ));
            }
            // Never publish something we would refuse ourselves.
            verify_chain(&chain, domain, crate::now(), &TrustAnchors::default())
                .map_err(|e| format!("collected chain {e}"))?;
            return Ok(chain);
        }
        let ds = ask(upstream, &zone, RecordType::DS, timeout).await?;
        let parent = signer_of(&ds, &zone, RecordType::DS)
            .ok_or_else(|| format!("{zone} DS is not signed"))?;
        out.extend(ds);
        zone = parent;
    }
    Err("too many zones".into())
}

/// Resolvers to collect a chain from when none are configured: the
/// system's, then two public validating ones — a local stub often strips
/// DNSSEC records. Only the domain's own public records are asked for.
pub fn default_upstreams() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = hickory_resolver::system_conf::read_system_conf()
        .map(|(c, _)| c.name_servers().iter().map(|ns| ns.ip).collect())
        .unwrap_or_default();
    for ip in ["9.9.9.9", "1.1.1.1"] {
        let ip: IpAddr = ip.parse().expect("literal");
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// [`build_chain`] from the first of `upstreams` that yields a valid one.
pub async fn build_chain_any(
    domain: &str,
    upstreams: &[IpAddr],
    timeout: Duration,
) -> Result<String, String> {
    let mut errors = Vec::new();
    for ip in upstreams {
        match build_chain(domain, *ip, timeout).await {
            Ok(c) => return Ok(c),
            Err(e) => errors.push(e),
        }
    }
    Err(errors.join("; "))
}

/// The signer of the RRSIG over (name, ty) among `records`.
fn signer_of(records: &[Record], name: &Name, ty: RecordType) -> Option<Name> {
    records.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s))
            if (&r.name) == name && s.input().type_covered == ty =>
        {
            Some(s.input().signer_name.clone())
        }
        _ => None,
    })
}

/// One query with DO set: the answer section (RRset + RRSIGs). UDP with a
/// 1232-byte buffer, TCP when truncated (root DNSKEY answers often are).
async fn ask(
    upstream: IpAddr,
    name: &Name,
    ty: RecordType,
    timeout: Duration,
) -> Result<Vec<Record>, String> {
    let id: u16 = rand_id();
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name.clone(), ty));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(1232);
    msg.set_edns(edns);
    let bytes = msg.to_vec().map_err(|e| e.to_string())?;
    let addr = SocketAddr::new(upstream, 53);
    let reply = tokio::time::timeout(timeout, async {
        let bind: SocketAddr = if upstream.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        sock.send_to(&bytes, addr).await?;
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if from == addr && n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return Ok::<_, std::io::Error>(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| format!("{upstream}: no answer for {name} {ty}"))?
    .map_err(|e| e.to_string())?;
    let mut parsed = Message::from_vec(&reply).map_err(|e| e.to_string())?;
    if parsed.metadata.truncation {
        let reply = tokio::time::timeout(timeout, async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut s = tokio::net::TcpStream::connect(addr).await?;
            s.write_all(&(bytes.len() as u16).to_be_bytes()).await?;
            s.write_all(&bytes).await?;
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await?;
            let mut r = vec![0u8; u16::from_be_bytes(hdr) as usize];
            s.read_exact(&mut r).await?;
            Ok::<_, std::io::Error>(r)
        })
        .await
        .map_err(|_| format!("{upstream}: no TCP answer for {name} {ty}"))?
        .map_err(|e| e.to_string())?;
        parsed = Message::from_vec(&reply).map_err(|e| e.to_string())?;
    }
    let records: Vec<Record> = parsed
        .answers
        .into_iter()
        .filter(|r| (&r.name) == name)
        .collect();
    if records.is_empty() {
        return Err(format!("{upstream}: empty answer for {name} {ty}"));
    }
    Ok(records)
}

fn rand_id() -> u16 {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (n ^ (n >> 16)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_resolver::proto::dnssec::rdata::SigInput;
    use hickory_resolver::proto::dnssec::{Algorithm, DigestType, SigningKey, TBS};
    use hickory_resolver::proto::rr::SerialNumber;
    use hickory_resolver::proto::rr::rdata::TXT;
    use pubdom_core::Npub;

    const NOW: u64 = 1_800_000_000;

    /// A zone key: flags 257 (KSK) or 256 (ZSK).
    struct Key {
        signing: Box<dyn SigningKey>,
        dnskey: DNSKEY,
    }

    fn key(flags: u16) -> Key {
        let alg = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(alg).unwrap();
        let signing = Box::new(EcdsaSigningKey::from_pkcs8(&pkcs8, alg).unwrap());
        let dnskey = DNSKEY::with_flags(flags, signing.to_public_key().unwrap());
        Key { signing, dnskey }
    }

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    /// The RRSIG over `set` by `k` of zone `signer`, valid [inc, exp].
    fn sign(set: &[Record], k: &Key, signer: &Name, inc: u64, exp: u64) -> Record {
        let owner = set[0].name.clone();
        let input = SigInput {
            type_covered: set[0].record_type(),
            algorithm: k.dnskey.algorithm(),
            num_labels: owner.num_labels(),
            original_ttl: set[0].ttl,
            sig_expiration: SerialNumber::new(exp as u32),
            sig_inception: SerialNumber::new(inc as u32),
            key_tag: k.dnskey.calculate_key_tag().unwrap(),
            signer_name: signer.clone(),
        };
        let tbs = TBS::from_input(&owner, DNSClass::IN, &input, set.iter()).unwrap();
        let sig = k.signing.sign(&tbs).unwrap();
        Record::from_rdata(
            owner,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
        )
    }

    fn dnskeys(zone: &Name, keys: &[&Key]) -> Vec<Record> {
        keys.iter()
            .map(|k| {
                Record::from_rdata(
                    zone.clone(),
                    3600,
                    RData::DNSSEC(DNSSECRData::DNSKEY(k.dnskey.clone())),
                )
            })
            .collect()
    }

    fn ds(zone: &Name, k: &Key) -> Vec<Record> {
        let digest = k.dnskey.to_digest(zone, DigestType::SHA256).unwrap();
        let d = DS::new(
            k.dnskey.calculate_key_tag().unwrap(),
            k.dnskey.algorithm(),
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        );
        vec![Record::from_rdata(
            zone.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DS(d)),
        )]
    }

    fn author() -> Npub {
        Npub::from_bytes([7; 32])
    }

    /// A signed hierarchy root → org → example.org with a split KSK/ZSK in
    /// example.org, and the anchors trusting this test root.
    struct World {
        root: Key,
        org: Key,
        ksk: Key,
        zsk: Key,
        anchors: TrustAnchors,
    }

    fn world() -> World {
        let root = key(257);
        let mut anchors = TrustAnchors::empty();
        anchors.insert(root.dnskey.public_key());
        World {
            root,
            org: key(257),
            ksk: key(257),
            zsk: key(256),
            anchors,
        }
    }

    impl World {
        /// Every record of the chain; `window` is every signature's validity.
        fn records(&self, txt: &str, window: (u64, u64)) -> Vec<Record> {
            let (inc, exp) = window;
            let (root, org, ex) = (name("."), name("org."), name("example.org."));
            let owner = name("_fips-dns.example.org.");
            let mut out = Vec::new();
            let set = vec![Record::from_rdata(
                owner,
                300,
                RData::TXT(TXT::new(vec![txt.to_string()])),
            )];
            out.push(sign(&set, &self.zsk, &ex, inc, exp));
            out.extend(set);
            for (zone, keys, signer) in [
                (&ex, vec![&self.ksk, &self.zsk], &self.ksk),
                (&org, vec![&self.org], &self.org),
                (&root, vec![&self.root], &self.root),
            ] {
                let set = dnskeys(zone, &keys);
                out.push(sign(&set, signer, zone, inc, exp));
                out.extend(set);
            }
            let set = ds(&ex, &self.ksk);
            out.push(sign(&set, &self.org, &org, inc, exp));
            out.extend(set);
            let set = ds(&org, &self.org);
            out.push(sign(&set, &self.root, &root, inc, exp));
            out.extend(set);
            out
        }

        fn chain(&self) -> String {
            let txt = format!("v=fips1 npub={}", author());
            encode_chain(&self.records(&txt, (NOW - 3600, NOW + 86400))).unwrap()
        }
    }

    fn claim(chain: String, author: Npub) -> Claim {
        Claim {
            author,
            domain: "example.org".into(),
            port: 5355,
            created_at: NOW,
            dnssec: Some(chain),
        }
    }

    #[test]
    fn a_complete_chain_verifies_and_names_the_author() {
        let w = world();
        let chain = w.chain();
        let p = verify_chain(&chain, "example.org", NOW, &w.anchors).unwrap();
        assert_eq!(p.records[0].npub, author());
        assert_eq!(p.expires, NOW + 86400);
        let proofs = DnssecProofs {
            anchors: w.anchors.clone(),
        };
        assert!(proofs.verify(&claim(chain.clone(), author()), NOW));
        assert_eq!(
            proofs.check(&claim(chain.clone(), Npub::from_bytes([8; 32])), NOW),
            Err(ProofError::NotNamed)
        );
        // For another domain the same chain proves nothing.
        let mut other = claim(chain, author());
        other.domain = "example.net".into();
        assert!(!proofs.verify(&other, NOW));
    }

    #[test]
    fn signatures_outside_their_window_are_refused() {
        let w = world();
        let chain = w.chain();
        for now in [NOW - 7200, NOW + 86401] {
            assert!(matches!(
                verify_chain(&chain, "example.org", now, &w.anchors),
                Err(ProofError::Unsigned(_))
            ));
        }
    }

    #[test]
    fn an_unanchored_root_or_a_broken_link_is_refused() {
        let w = world();
        let chain = w.chain();
        // The real root anchors do not trust the test root.
        assert!(verify_chain(&chain, "example.org", NOW, &TrustAnchors::default()).is_err());
        // Drop the DS of example.org: its keys are no longer vouched for.
        let recs: Vec<Record> = w
            .records(
                &format!("v=fips1 npub={}", author()),
                (NOW - 3600, NOW + 86400),
            )
            .into_iter()
            .filter(|r| !(r.record_type() == RecordType::DS && r.name == name("example.org.")))
            .collect();
        let broken = encode_chain(&recs).unwrap();
        assert!(verify_chain(&broken, "example.org", NOW, &w.anchors).is_err());
        // A TXT RRset swapped for another text fails its signature.
        let mut recs = w.records(
            &format!("v=fips1 npub={}", author()),
            (NOW - 3600, NOW + 86400),
        );
        for r in &mut recs {
            if r.record_type() == RecordType::TXT {
                let other = format!("v=fips1 npub={}", Npub::from_bytes([9; 32]));
                r.data = RData::TXT(TXT::new(vec![other]));
            }
        }
        let forged = encode_chain(&recs).unwrap();
        assert!(verify_chain(&forged, "example.org", NOW, &w.anchors).is_err());
        // Garbage is an encoding error, not a panic.
        assert!(matches!(
            verify_chain("not base64!", "example.org", NOW, &w.anchors),
            Err(ProofError::Encoding(_))
        ));
        assert!(verify_chain("AAAA", "example.org", NOW, &w.anchors).is_err());
    }

    #[test]
    fn a_signature_by_a_zone_below_is_refused() {
        // example.org's key signing org's DS for example.org is not the
        // parent vouching; nor may a zone sign names outside itself.
        let w = world();
        let (org, ex) = (name("org."), name("example.org."));
        let mut recs = w.records(
            &format!("v=fips1 npub={}", author()),
            (NOW - 3600, NOW + 86400),
        );
        recs.retain(|r| {
            !(r.name == ex
                && matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == RecordType::DS))
        });
        let set = ds(&ex, &w.ksk);
        recs.push(sign(&set, &w.ksk, &ex, NOW - 3600, NOW + 86400));
        let chain = encode_chain(&recs).unwrap();
        assert!(verify_chain(&chain, "example.org", NOW, &w.anchors).is_err());
        let _ = org;
    }

    /// Against the live DNS: `PUBDOM_LIVE_DOMAIN=<a signed domain with a
    /// _fips-dns record> cargo test -p pubdom-resolve live -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_chain_builds_and_verifies() {
        let domain = std::env::var("PUBDOM_LIVE_DOMAIN").expect("PUBDOM_LIVE_DOMAIN");
        let upstream: IpAddr = std::env::var("PUBDOM_LIVE_UPSTREAM")
            .unwrap_or_else(|_| "9.9.9.9".into())
            .parse()
            .unwrap();
        let chain = build_chain(&domain, upstream, Duration::from_secs(3))
            .await
            .unwrap();
        let p = verify_chain(&chain, &domain, crate::now(), &TrustAnchors::default()).unwrap();
        println!(
            "{} bytes, {} records naming {:?}, valid until {}",
            chain.len(),
            p.records.len(),
            p.records
                .iter()
                .map(|r| r.npub.to_string())
                .collect::<Vec<_>>(),
            p.expires
        );
    }
}
