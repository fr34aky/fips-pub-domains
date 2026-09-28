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
use pubdom_core::policy::{ProofVerifier, ProvenRecord};
use pubdom_core::txt::TxtRecord;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// Longest chain accepted: a TXT record a few zones deep is well under
/// 10 KB even with RSA keys; nothing legitimate comes near this.
const MAX_CHAIN_BYTES: usize = 64 * 1024;
/// Zones walked from the TXT record up to the root when collecting.
const MAX_ZONES: usize = 16;

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
    /// Inception of the TXT RRset's signature: which of two valid proofs
    /// shows the newer record.
    pub signed_at: u64,
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
        memo: RefCell::new(HashMap::new()),
        budget: Cell::new(MAX_SIG_CHECKS),
    };
    let valid = v
        .rrset(&owner, RecordType::TXT)
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
        signed_at: valid.inception,
        expires: valid.expires,
    })
}

/// Signature verifications one proof may cost. A real chain needs one per
/// RRset (six or so); the budget stops a crafted chain full of forged
/// RRSIGs from making validation expensive.
const MAX_SIG_CHECKS: u32 = 64;
/// A signature whose inception is up to this far in the future is
/// accepted: offline nodes often run without NTP. Expiration is strict.
const INCEPTION_SKEW: u64 = 3600;

/// A validated RRset: when the signature relied on was made, and the
/// earliest expiration of everything it rests on.
#[derive(Clone, Copy)]
struct Valid {
    inception: u64,
    expires: u64,
}

/// A validation result, as memoized.
type Checked = Result<Valid, String>;

struct Validator<'a> {
    records: &'a [Record],
    now: u64,
    anchors: &'a TrustAnchors,
    /// Each RRset is validated once; `None` marks one in progress, so a
    /// cycle in a crafted chain fails instead of recursing.
    memo: RefCell<HashMap<(Name, RecordType), Option<Checked>>>,
    budget: Cell<u32>,
}

impl Validator<'_> {
    /// The RRset (name, type), without signatures.
    fn set(&self, name: &Name, ty: RecordType) -> Vec<&Record> {
        self.records
            .iter()
            .filter(|r| r.record_type() == ty && &r.name == name && r.dns_class == DNSClass::IN)
            .collect()
    }

    fn sigs(&self, name: &Name, ty: RecordType) -> Vec<&RRSIG> {
        self.records
            .iter()
            .filter(|r| &r.name == name && r.dns_class == DNSClass::IN)
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

    /// Validate the RRset (name, ty), once.
    fn rrset(&self, name: &Name, ty: RecordType) -> Result<Valid, String> {
        let key = (name.clone(), ty);
        match self.memo.borrow().get(&key) {
            Some(Some(r)) => return r.clone(),
            Some(None) => return Err(format!("{name} {ty}: the chain is circular")),
            None => {}
        }
        self.memo.borrow_mut().insert(key.clone(), None);
        let r = self.rrset_uncached(name, ty);
        self.memo.borrow_mut().insert(key, Some(r.clone()));
        r
    }

    /// Some current RRSIG over the RRset by a key of its zone whose DNSKEY
    /// RRset validates in turn.
    fn rrset_uncached(&self, name: &Name, ty: RecordType) -> Result<Valid, String> {
        let set = self.set(name, ty);
        if set.is_empty() {
            return Err(format!("no {ty} at {name}"));
        }
        let mut why = format!("no RRSIG over {name} {ty}");
        for sig in self.sigs(name, ty) {
            let input = sig.input();
            let signer = &input.signer_name;
            // The signer is the zone owning the name: an ancestor (or the
            // name itself); a DS record is signed by a zone above it, never
            // by the zone it describes; a DNSKEY RRset only by its own zone.
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
            if self.now + INCEPTION_SKEW < inception || self.now > expiration {
                why = format!(
                    "{name} {ty}: signature not valid now (valid {inception}..{expiration})"
                );
                continue;
            }
            // The keys this signature may be made with, and when what makes
            // them trusted expires.
            let (keys, below) = if ty == RecordType::DNSKEY {
                // The zone's own key set, self-signed: the signing key must be
                // anchored (root) or covered by a validated DS.
                match self.anchored_keys(name) {
                    Ok(k) => k,
                    Err(e) => {
                        why = e;
                        continue;
                    }
                }
            } else {
                match self.rrset(signer, RecordType::DNSKEY) {
                    Ok(v) => (self.keys(signer), v.expires),
                    Err(e) => {
                        why = e;
                        continue;
                    }
                }
            };
            for k in keys {
                if k.algorithm() != input.algorithm
                    || k.calculate_key_tag().ok() != Some(input.key_tag)
                {
                    continue;
                }
                let left = self.budget.get();
                if left == 0 {
                    return Err("too many signatures to check".into());
                }
                self.budget.set(left - 1);
                if k.verify_rrsig(name, DNSClass::IN, sig, set.iter().copied())
                    .is_ok()
                {
                    return Ok(Valid {
                        inception,
                        expires: expiration.min(below),
                    });
                }
            }
            why = format!("{name} {ty}: signature does not verify");
        }
        Err(why)
    }

    /// The keys of `zone` that are trust points — in the anchors (root), or
    /// covered by a validated DS RRset from above — and when that expires.
    fn anchored_keys(&self, zone: &Name) -> Result<(Vec<&DNSKEY>, u64), String> {
        let keys = self.keys(zone);
        if zone.is_root() {
            let k: Vec<&DNSKEY> = keys
                .into_iter()
                .filter(|k| self.anchors.contains(k.public_key()))
                .collect();
            return if k.is_empty() {
                Err("root DNSKEY RRset holds no trust anchor".into())
            } else {
                Ok((k, u64::MAX))
            };
        }
        let ds_valid = self.rrset(zone, RecordType::DS)?;
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
            Ok((k, ds_valid.expires))
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
    fn verify(&self, claim: &Claim, now: u64) -> Option<ProvenRecord> {
        match self.check(claim, now) {
            Ok(p) => Some(p.into()),
            Err(e) => {
                tracing::debug!(domain = %claim.domain, author = %claim.author, error = %e, "claim's DNSSEC proof rejected");
                None
            }
        }
    }
}

impl From<Proven> for ProvenRecord {
    fn from(p: Proven) -> Self {
        ProvenRecord {
            signed_at: p.signed_at,
            named: p.records.iter().map(|r| r.npub).collect(),
        }
    }
}

/// Collect the chain for `_fips-dns.<domain>` from `upstream`, a recursive
/// resolver that returns DNSSEC records when asked with the DO bit (most
/// public ones do; a stub that strips them yields "no RRSIG").
/// Returns the chain and what it proves.
pub async fn build_chain(
    domain: &str,
    upstream: IpAddr,
    timeout: Duration,
) -> Result<(String, Proven), String> {
    let owner = Name::from_str(&format!("{}.", txt_name(domain))).map_err(|e| e.to_string())?;
    let mut out: Vec<Record> = Vec::new();
    // The TXT RRset; its RRSIG's signer is the zone to walk up from.
    let txt = ask(upstream, &owner, RecordType::TXT, timeout).await?;
    let mut zone = signer_of(&txt, &owner, RecordType::TXT)
        .ok_or_else(|| format!("{owner} TXT is not signed (is the zone DNSSEC-signed?)"))?;
    out.extend(txt);
    for _ in 0..MAX_ZONES {
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
            let proven = verify_chain(&chain, domain, crate::now(), &TrustAnchors::default())
                .map_err(|e| format!("collected chain {e}"))?;
            return Ok((chain, proven));
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
) -> Result<(String, Proven), String> {
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
    // Random: the answer is checked anyway, but a guessable ID would let an
    // off-path attacker make the build fail.
    let id: u16 = rand::random();
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
        let shown = proofs.verify(&claim(chain.clone(), author()), NOW).unwrap();
        assert_eq!(shown.named, vec![author()]);
        assert_eq!(shown.signed_at, NOW - 3600);
        assert_eq!(
            proofs.check(&claim(chain.clone(), Npub::from_bytes([8; 32])), NOW),
            Err(ProofError::NotNamed)
        );
        // For another domain the same chain proves nothing.
        let mut other = claim(chain, author());
        other.domain = "example.net".into();
        assert!(proofs.verify(&other, NOW).is_none());
    }

    #[test]
    fn signatures_outside_their_window_are_refused() {
        let w = world();
        let chain = w.chain();
        for now in [NOW - 3600 - INCEPTION_SKEW - 1, NOW + 86401] {
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
    fn a_signature_by_the_wrong_zone_is_refused() {
        let w = world();
        let ex = name("example.org.");
        let txt = format!("v=fips1 npub={}", author());
        let window = (NOW - 3600, NOW + 86400);
        let is_sig_over = |r: &Record, ty: RecordType| matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == ty);
        // example.org's own key signing its DS is not its parent vouching.
        let mut recs = w.records(&txt, window);
        recs.retain(|r| !(r.name == ex && is_sig_over(r, RecordType::DS)));
        recs.push(sign(&ds(&ex, &w.ksk), &w.ksk, &ex, window.0, window.1));
        let chain = encode_chain(&recs).unwrap();
        assert!(verify_chain(&chain, "example.org", NOW, &w.anchors).is_err());
        // A zone may not sign names outside itself: example.org's key over
        // org's DS, naming example.org as the signer.
        let org = name("org.");
        let mut recs = w.records(&txt, window);
        recs.retain(|r| !(r.name == org && is_sig_over(r, RecordType::DS)));
        recs.push(sign(&ds(&org, &w.org), &w.zsk, &ex, window.0, window.1));
        let chain = encode_chain(&recs).unwrap();
        assert!(verify_chain(&chain, "example.org", NOW, &w.anchors).is_err());
    }

    #[test]
    fn a_chain_full_of_forged_signatures_stays_cheap() {
        // Dozens of RRSIGs with the right key tag but garbage signatures on
        // every RRset: validation gives up after its budget instead of
        // multiplying the work per level.
        let w = world();
        let window = (NOW - 3600, NOW + 86400);
        let mut recs = w.records(&format!("v=fips1 npub={}", author()), window);
        let sigs: Vec<Record> = recs
            .iter()
            .filter(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(_))))
            .cloned()
            .collect();
        for s in &sigs {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &s.data else {
                unreachable!()
            };
            for i in 0..40u8 {
                let mut bad = rrsig.sig().to_vec();
                bad[0] ^= i.wrapping_add(1);
                let forged = RRSIG::from_sig(rrsig.input().clone(), bad);
                recs.insert(
                    0,
                    Record::from_rdata(
                        s.name.clone(),
                        3600,
                        RData::DNSSEC(DNSSECRData::RRSIG(forged)),
                    ),
                );
            }
        }
        let chain = encode_chain(&recs).unwrap();
        let start = std::time::Instant::now();
        assert!(verify_chain(&chain, "example.org", NOW, &w.anchors).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_slightly_slow_clock_is_tolerated_on_inception_only() {
        let w = world();
        let chain = w.chain();
        // Signed an hour before NOW: a clock up to an hour behind that
        // still accepts it; expiration has no slack.
        assert!(verify_chain(&chain, "example.org", NOW - 3600 - 1800, &w.anchors).is_ok());
        assert!(verify_chain(&chain, "example.org", NOW - 3600 - 3601, &w.anchors).is_err());
        assert!(verify_chain(&chain, "example.org", NOW + 86401, &w.anchors).is_err());
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
        let (chain, _) = build_chain(&domain, upstream, Duration::from_secs(3))
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
