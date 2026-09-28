//! The verification precedence (spec §5.1), redundant servers and conflicts
//! (§5.3), pin changes (§5.4) and the offline path (§5.5), as one pure
//! function over what the resolver gathered.
//!
//! "Refused" applies to the *binding*, never to the name: every negative
//! outcome is [`Decision::NotOverFips`], which the resolver turns into a
//! legacy passthrough when online and into the ordinary offline failure
//! otherwise (spec §5.1, §7).

use crate::claim::{Claim, Event, ZoneRecord};
use crate::domain::is_claimable;
use crate::identity::Npub;
use crate::pins::{Binding, Method, PinStore, SeenKey};
use crate::txt::TxtRecord;
use crate::{KIND_CLAIM, KIND_ZONE, MAX_FUTURE_SECS};

/// What the legacy DNS said about `_fips-dns.<domain>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxtLookup {
    /// Records found; `method` is how strongly the answer was authenticated.
    Hit {
        records: Vec<TxtRecord>,
        method: Method,
    },
    /// DNS answered and there is no such record: the domain does not
    /// participate (any more). `method` is how strongly the *denial* was
    /// authenticated — a validated NSEC/NSEC3 denial is `Dnssec`, two
    /// agreeing upstreams `Dns`, one `DnsSingle` — because forgetting a pin
    /// is a binding change and must not be cheaper than making one.
    Miss { method: Method },
    /// No upstream could be asked: offline, or every upstream failed.
    Unreachable,
    /// Upstreams answered but disagree, with no majority among the answers
    /// that count (the validated ones, when there are any). Online, so not
    /// the offline path — no relay is asked and nothing unverified is used;
    /// pins keep resolving.
    Disputed,
}

/// Why a name is not over fips. Logged, never shown as an error to the
/// application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    PublicSuffix,
    NoTxt,
    NoClaim,
    /// Claims exist but none is authored by a key the TXT record names.
    ClaimMismatch,
    /// Offline, no pin, no proof: the claim cannot be verified.
    Unverified,
    /// Offline, several unverifiable claims by different authors.
    Conflict,
    /// Upstream resolvers disagree on the record (and nothing is pinned).
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Resolve over the mesh through these servers, primary first. Every
    /// entry is verified (or pinned); the resolver fails over along the list.
    Bound(Vec<Binding>),
    /// Resolve, but only because the user opted into unverified offline
    /// bindings; must be surfaced as such (spec §5.1 step 5).
    Unverified(Binding),
    NotOverFips(Reason),
}

/// One change to the domain's pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinChange {
    Put(Binding),
    Forget(Npub),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    pub changes: Vec<PinChange>,
}

/// Verifies the `dnssec` proof carried in a claim against the DNS root
/// trust anchor (spec §3.1, §5.5); `pubdom-resolve::proof` implements it.
/// [`NoProofs`] is the `dnssec: false` switch.
pub trait ProofVerifier {
    /// The record the claim's proof shows, if it validates at `now`
    /// (signatures expire) and names the claim's author.
    fn verify(&self, claim: &Claim, now: u64) -> Option<ProvenRecord>;
}

/// What a valid proof shows: the `_fips-dns` record's npubs, and when its
/// signature was made — of two valid proofs, the newer record counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenRecord {
    pub signed_at: u64,
    pub named: Vec<Npub>,
}

pub struct NoProofs;
impl ProofVerifier for NoProofs {
    fn verify(&self, _: &Claim, _: u64) -> Option<ProvenRecord> {
        None
    }
}

pub struct Input<'a> {
    pub domain: &'a str,
    /// The domain's pinned servers, primary first; empty when unpinned.
    pub pins: Vec<Binding>,
    pub txt: TxtLookup,
    /// Claims for `domain`, already passed through [`ingest_claims`].
    pub claims: &'a [Claim],
    pub now: u64,
    pub allow_unverified_offline: bool,
    pub proofs: &'a dyn ProofVerifier,
}

pub fn decide(input: Input<'_>) -> Outcome {
    let keep = |decision| Outcome {
        decision,
        changes: Vec::new(),
    };

    if !is_claimable(input.domain) {
        return keep(Decision::NotOverFips(Reason::PublicSuffix));
    }

    match &input.txt {
        TxtLookup::Hit { records, method } => {
            let named: Vec<Npub> = records.iter().map(|r| r.npub).collect();
            let pinned_named: Vec<&Binding> = input
                .pins
                .iter()
                .filter(|p| named.contains(&p.npub))
                .collect();
            let mut matching: Vec<&Claim> = input
                .claims
                .iter()
                .filter(|c| named.contains(&c.author))
                .collect();
            // A pinned server the record no longer names: dropping it is a
            // binding change, accepted only with a verification at least as
            // strong as its pin — whether or not a claim reached us, else a
            // retired key would stay pinned for the next offline lookup. A
            // weaker record leaves it pinned, after the named ones.
            let mut unnamed_kept = Vec::new();
            let mut changes = Vec::new();
            for pin in input.pins.iter().filter(|p| !named.contains(&p.npub)) {
                if *method >= pin.method {
                    changes.push(PinChange::Forget(pin.npub));
                } else {
                    unnamed_kept.push(pin.clone());
                }
            }
            if matching.is_empty() {
                // DNS says the domain participates but no reachable relay
                // carries a claim. Pins the record still names resolve (spec
                // §5.1 step 2): their claims were verified when they were
                // pinned, and the record vouches for the same keys today.
                // Otherwise not over fips.
                if !pinned_named.is_empty() {
                    let mut servers: Vec<Binding> = pinned_named.into_iter().cloned().collect();
                    servers.extend(unnamed_kept);
                    return Outcome {
                        decision: Decision::Bound(servers),
                        changes,
                    };
                }
                let reason = if input.claims.is_empty() {
                    Reason::NoClaim
                } else {
                    Reason::ClaimMismatch
                };
                return Outcome {
                    decision: Decision::NotOverFips(reason),
                    changes,
                };
            }

            // Every key the record names and that claims the domain is a
            // server (spec §5.3): the servers already pinned keep their
            // place, new ones follow, newest claim first.
            let pin_order = |npub: Npub| input.pins.iter().position(|p| p.npub == npub);
            matching.sort_by(|a, b| match (pin_order(a.author), pin_order(b.author)) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => b.created_at.cmp(&a.created_at),
            });
            let mut servers = Vec::new();
            for claim in matching {
                let existing = input.pins.iter().find(|p| p.npub == claim.author);
                if let Some(pin) = existing
                    && (*method < pin.method || (*method == pin.method && claim.port == pin.port))
                {
                    // Weaker than what the pin rests on (spec §5.4): the
                    // binding is not downgraded — else an unsigned replay of
                    // the real record would lower the bar for the change
                    // that follows. Equal and unchanged: nothing to write;
                    // `verified_at` records when the binding took this form.
                    servers.push(pin.clone());
                    continue;
                }
                let fresh = Binding {
                    domain: input.domain.to_owned(),
                    npub: claim.author,
                    port: claim.port,
                    method: *method,
                    verified_at: input.now,
                };
                servers.push(fresh.clone());
                changes.push(PinChange::Put(fresh));
            }
            // Named, but no claim reached us: still a server.
            for pin in &pinned_named {
                if !servers.iter().any(|s| s.npub == pin.npub) {
                    servers.push((*pin).clone());
                }
            }
            servers.extend(unnamed_kept);
            Outcome {
                decision: Decision::Bound(servers),
                changes,
            }
        }

        TxtLookup::Miss { method } => {
            // The operator withdrew (or never had) the record: the domain is
            // legacy-only now. Forgetting a pin is a binding change, so it
            // takes a denial at least as strong as the pin (a captive
            // portal's NXDOMAIN must not unpin a DNSSEC binding). A weaker
            // denial keeps the pin but does not use it while DNS says no.
            let changes = input
                .pins
                .iter()
                .filter(|p| *method >= p.method)
                .map(|p| PinChange::Forget(p.npub))
                .collect();
            Outcome {
                decision: Decision::NotOverFips(Reason::NoTxt),
                changes,
            }
        }

        TxtLookup::Disputed => {
            if input.pins.is_empty() {
                keep(Decision::NotOverFips(Reason::Disputed))
            } else {
                keep(Decision::Bound(input.pins.clone()))
            }
        }

        TxtLookup::Unreachable => {
            // Offline, a proof carried in a claim stands in for the record
            // (spec §5.5). Proofs may show different versions of it — a
            // retired key's claim can carry a chain signed before the change
            // and still valid — so the newest proven record decides, as the
            // live record would online.
            let newest = match newest_proof(&input) {
                Ok(n) => n,
                // Two different records signed at the same time: nothing to
                // tell them apart by.
                Err(()) if input.pins.is_empty() => {
                    return keep(Decision::NotOverFips(Reason::Conflict));
                }
                Err(()) => None,
            };
            if !input.pins.is_empty() {
                let Some(record) = newest else {
                    return keep(Decision::Bound(input.pins.clone()));
                };
                // A pin resting on evidence older than the newest proven
                // record, which no longer names it, is retired; everything
                // else stays, and keys the record names that have a claim
                // join as servers.
                let mut servers = Vec::new();
                let mut changes = Vec::new();
                for pin in &input.pins {
                    if record.named.contains(&pin.npub) || pin.verified_at >= record.signed_at {
                        servers.push(pin.clone());
                    } else {
                        changes.push(PinChange::Forget(pin.npub));
                    }
                }
                for b in proven_servers(&input, &record) {
                    if !servers.iter().any(|s| s.npub == b.npub) {
                        changes.push(PinChange::Put(b.clone()));
                        servers.push(b);
                    }
                }
                return Outcome {
                    decision: Decision::Bound(servers),
                    changes,
                };
            }
            if let Some(record) = newest {
                let servers = proven_servers(&input, &record);
                return Outcome {
                    changes: servers.iter().cloned().map(PinChange::Put).collect(),
                    decision: Decision::Bound(servers),
                };
            }
            if input.claims.is_empty() {
                return keep(Decision::NotOverFips(Reason::NoClaim));
            }
            if !input.allow_unverified_offline {
                return keep(Decision::NotOverFips(Reason::Unverified));
            }
            let mut authors: Vec<_> = input.claims.iter().map(|c| c.author).collect();
            authors.sort();
            authors.dedup();
            if authors.len() > 1 {
                return keep(Decision::NotOverFips(Reason::Conflict));
            }
            let c = input
                .claims
                .iter()
                .max_by_key(|c| c.created_at)
                .expect("non-empty");
            keep(Decision::Unverified(Binding {
                domain: input.domain.to_owned(),
                npub: c.author,
                port: c.port,
                method: Method::Unverified,
                verified_at: input.now,
            }))
        }
    }
}

/// The newest record any claim's proof shows (by its signature's
/// inception). `Err` when two different records share that time.
fn newest_proof(input: &Input<'_>) -> Result<Option<ProvenRecord>, ()> {
    let mut proven: Vec<ProvenRecord> = input
        .claims
        .iter()
        .filter(|c| c.dnssec.is_some())
        .filter_map(|c| input.proofs.verify(c, input.now))
        .map(|mut p| {
            p.named.sort();
            p.named.dedup();
            p
        })
        .collect();
    let Some(top) = proven.iter().map(|p| p.signed_at).max() else {
        return Ok(None);
    };
    proven.retain(|p| p.signed_at == top);
    if proven.iter().any(|p| p.named != proven[0].named) {
        return Err(());
    }
    Ok(proven.pop())
}

/// Every key `record` names that has a claim, as a DNSSEC binding, newest
/// claim first. `verified_at` is when the record was signed: the age of the
/// evidence, so a newer proven record can supersede it later.
fn proven_servers(input: &Input<'_>, record: &ProvenRecord) -> Vec<Binding> {
    let mut named: Vec<&Claim> = input
        .claims
        .iter()
        .filter(|c| record.named.contains(&c.author))
        .collect();
    named.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    named
        .into_iter()
        .map(|c| Binding {
            domain: input.domain.to_owned(),
            npub: c.author,
            port: c.port,
            method: Method::Dnssec,
            verified_at: record.signed_at,
        })
        .collect()
}

/// Parse claim events for `domain`, drop what fails the limits, what is
/// dated in the future, and what is older than an event already seen from
/// the same author (relay rollback, spec §8); remember the rest.
pub fn ingest_claims(store: &dyn PinStore, domain: &str, events: &[Event], now: u64) -> Vec<Claim> {
    let mut out: Vec<Claim> = Vec::new();
    for ev in events {
        let Ok(claim) = Claim::parse(ev) else {
            continue;
        };
        if claim.domain != domain || claim.created_at > now + MAX_FUTURE_SECS {
            continue;
        }
        let key = SeenKey {
            kind: KIND_CLAIM,
            author: claim.author,
            domain: claim.domain.clone(),
        };
        if let Some(seen) = store.newest_seen(&key)
            && claim.created_at < seen
        {
            continue;
        }
        store.note_seen(key, claim.created_at);
        // One claim per author: addressable events replace each other.
        match out.iter_mut().find(|c| c.author == claim.author) {
            Some(existing) if existing.created_at < claim.created_at => *existing = claim,
            Some(_) => {}
            None => out.push(claim),
        }
    }
    out
}

/// The newest zone record for `domain` by `author` (a pinned server),
/// with the same future and rollback filters as claims (spec §3.3, §8).
/// Records by anyone else are ignored: only the domain's servers may say
/// which nodes serve its names.
pub fn ingest_zone(
    store: &dyn PinStore,
    domain: &str,
    author: Npub,
    events: &[Event],
    now: u64,
) -> Option<ZoneRecord> {
    let mut best: Option<ZoneRecord> = None;
    for ev in events {
        let Ok(zone) = ZoneRecord::parse(ev) else {
            continue;
        };
        if zone.domain != domain || zone.author != author || zone.created_at > now + MAX_FUTURE_SECS
        {
            continue;
        }
        let key = SeenKey {
            kind: KIND_ZONE,
            author,
            domain: domain.to_owned(),
        };
        if let Some(seen) = store.newest_seen(&key)
            && zone.created_at < seen
        {
            continue;
        }
        store.note_seen(key, zone.created_at);
        if best.as_ref().is_none_or(|b| b.created_at < zone.created_at) {
            best = Some(zone);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pins::MemoryPinStore;

    const NOW: u64 = 1_790_000_000;
    fn npub(b: u8) -> Npub {
        Npub::from_bytes([b; 32])
    }
    fn claim(author: u8, created_at: u64) -> Claim {
        Claim {
            author: npub(author),
            domain: "example.org".into(),
            port: 5355,
            created_at,
            dnssec: None,
        }
    }
    fn txt(authors: &[u8], method: Method) -> TxtLookup {
        TxtLookup::Hit {
            records: authors
                .iter()
                .map(|a| TxtRecord {
                    npub: npub(*a),
                    port: Some(5355),
                })
                .collect(),
            method,
        }
    }
    fn pin(author: u8, method: Method) -> Binding {
        Binding {
            domain: "example.org".into(),
            npub: npub(author),
            port: 5355,
            method,
            verified_at: 1,
        }
    }
    fn run(pins: Vec<Binding>, txt_: TxtLookup, claims: &[Claim], allow: bool) -> Outcome {
        decide(Input {
            domain: "example.org",
            pins,
            txt: txt_,
            claims,
            now: NOW,
            allow_unverified_offline: allow,
            proofs: &NoProofs,
        })
    }
    fn bound(o: &Outcome) -> &[Binding] {
        match &o.decision {
            Decision::Bound(b) => b,
            other => panic!("expected Bound, got {other:?}"),
        }
    }
    fn npubs(o: &Outcome) -> Vec<Npub> {
        bound(o).iter().map(|b| b.npub).collect()
    }

    #[test]
    fn online_hit_with_matching_claim_binds_and_pins() {
        let o = run(vec![], txt(&[1], Method::Dnssec), &[claim(1, 5)], false);
        let b = &bound(&o)[0];
        assert_eq!(
            (b.npub, b.method, b.verified_at),
            (npub(1), Method::Dnssec, NOW)
        );
        assert_eq!(o.changes, vec![PinChange::Put(b.clone())]);
    }

    #[test]
    fn online_hit_without_matching_claim_is_legacy_and_drops_unnamed_pin() {
        let o = run(
            vec![pin(1, Method::Dns)],
            txt(&[2], Method::Dns),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::ClaimMismatch));
        // The record no longer names the pinned key, as strongly as the pin
        // was made: the key is retired even though the new one's claim did
        // not reach us — else it would answer the next offline lookup.
        assert_eq!(o.changes, vec![PinChange::Forget(npub(1))]);
        // A weaker record does not.
        let o = run(
            vec![pin(1, Method::Dnssec)],
            txt(&[2], Method::Dns),
            &[claim(1, 5)],
            false,
        );
        assert!(o.changes.is_empty());
        let o = run(vec![], txt(&[2], Method::Dns), &[], false);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoClaim));
    }

    #[test]
    fn pinned_server_still_named_by_txt_resolves_without_a_claim() {
        // Found on the phone: its relays did not carry the claim (it lived on
        // a relay inside the mesh), but the pin plus a TXT naming the same
        // key is a verified binding.
        let o = run(
            vec![pin(1, Method::Dnssec)],
            txt(&[1], Method::Dnssec),
            &[],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(1)]);
        assert!(o.changes.is_empty());
        // …but not when the record names someone else.
        let o = run(
            vec![pin(1, Method::Dnssec)],
            txt(&[2], Method::Dnssec),
            &[],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoClaim));
        assert_eq!(o.changes, vec![PinChange::Forget(npub(1))]);
        // One named pin resolves, an unnamed one is retired meanwhile.
        let o = run(
            vec![pin(1, Method::Dns), pin(3, Method::Dns)],
            txt(&[1, 2], Method::Dns),
            &[],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(1)]);
        assert_eq!(o.changes, vec![PinChange::Forget(npub(3))]);
    }

    #[test]
    fn disputed_record_keeps_pins_and_never_goes_offline() {
        // Resolvers disagree: pins resolve unchanged, and without one the
        // domain is legacy — never the unverified offline path, even opted in.
        let o = run(vec![pin(1, Method::Dns)], TxtLookup::Disputed, &[], true);
        assert_eq!(npubs(&o), vec![npub(1)]);
        assert!(o.changes.is_empty());
        let o = run(vec![], TxtLookup::Disputed, &[claim(2, 5)], true);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::Disputed));
    }

    #[test]
    fn unchanged_reverification_writes_nothing() {
        // Every TXT cache expiry re-verifies; an unchanged binding must not
        // rewrite the pin file each time.
        let o = run(
            vec![pin(1, Method::Dns)],
            txt(&[1], Method::Dns),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(1)]);
        assert!(o.changes.is_empty());
    }

    #[test]
    fn changed_binding_needs_equal_or_stronger_verification() {
        // Pinned via DNSSEC; today's answer is unsigned and names a new key.
        // The new key is accepted as a server (its own verification), but
        // the pinned one is not dropped by a weaker record.
        let o = run(
            vec![pin(1, Method::Dnssec)],
            txt(&[2], Method::Dns),
            &[claim(2, 5)],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(2), npub(1)]);
        assert_eq!(o.changes, vec![PinChange::Put(bound(&o)[0].clone())]);
        // Same strength: the old server is dropped.
        let o = run(
            vec![pin(1, Method::Dnssec)],
            txt(&[2], Method::Dnssec),
            &[claim(2, 5)],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(2)]);
        assert!(o.changes.contains(&PinChange::Forget(npub(1))));
        // Stronger than the pin: accepted, and the pin upgrades.
        let o = run(
            vec![pin(1, Method::DnsSingle)],
            txt(&[1], Method::Dnssec),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(bound(&o)[0].method, Method::Dnssec);
    }

    #[test]
    fn same_author_is_never_downgraded() {
        // An unsigned replay of the real record must not lower the pin's
        // method, or the next unsigned answer could move the binding.
        let o = run(
            vec![pin(1, Method::Dnssec)],
            txt(&[1], Method::DnsSingle),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(bound(&o)[0].method, Method::Dnssec);
        assert!(o.changes.is_empty());
    }

    #[test]
    fn several_named_servers_are_all_bound_pinned_first_then_newest() {
        let claims = [claim(1, 5), claim(2, 9), claim(3, 7)];
        let o = run(vec![], txt(&[1, 2, 3], Method::Dns), &claims, false);
        assert_eq!(
            npubs(&o),
            vec![npub(2), npub(3), npub(1)],
            "newest claim first without pins"
        );
        assert_eq!(o.changes.len(), 3);
        // Already pinned servers keep their order and come first.
        let o = run(
            vec![pin(3, Method::Dns), pin(1, Method::Dns)],
            txt(&[1, 2, 3], Method::Dns),
            &claims,
            false,
        );
        assert_eq!(npubs(&o), vec![npub(3), npub(1), npub(2)]);
        // A named server whose claim did not reach us this time stays a server.
        let o = run(
            vec![pin(1, Method::Dns), pin(2, Method::Dns)],
            txt(&[1, 2], Method::Dns),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(1), npub(2)]);
    }

    #[test]
    fn txt_miss_forgets_pins_only_with_a_denial_as_strong_as_each() {
        let miss = |m| TxtLookup::Miss { method: m };
        let o = run(
            vec![pin(1, Method::Dnssec), pin(2, Method::Dns)],
            miss(Method::Dns),
            &[],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoTxt));
        assert_eq!(
            o.changes,
            vec![PinChange::Forget(npub(2))],
            "the DNSSEC pin survives an unsigned denial"
        );
        let o = run(
            vec![pin(1, Method::Dnssec)],
            miss(Method::Dnssec),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(o.changes, vec![PinChange::Forget(npub(1))]);
        let o = run(vec![], miss(Method::DnsSingle), &[], false);
        assert!(o.changes.is_empty());
    }

    #[test]
    fn offline_uses_the_pins_and_refuses_the_rest() {
        let o = run(
            vec![pin(1, Method::Dns), pin(2, Method::Dns)],
            TxtLookup::Unreachable,
            &[claim(3, 5)],
            false,
        );
        assert_eq!(npubs(&o), vec![npub(1), npub(2)]);
        assert!(o.changes.is_empty());
        let o = run(vec![], TxtLookup::Unreachable, &[claim(2, 5)], false);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::Unverified));
        let o = run(vec![], TxtLookup::Unreachable, &[], false);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoClaim));
    }

    #[test]
    fn offline_opt_in_marks_a_single_claim_and_refuses_conflicts() {
        let o = run(vec![], TxtLookup::Unreachable, &[claim(2, 5)], true);
        match o.decision {
            Decision::Unverified(b) => {
                assert_eq!((b.npub, b.method), (npub(2), Method::Unverified))
            }
            other => panic!("{other:?}"),
        }
        assert!(o.changes.is_empty(), "unverified is never pinned");
        let o = run(
            vec![],
            TxtLookup::Unreachable,
            &[claim(2, 5), claim(3, 6)],
            true,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::Conflict));
    }

    #[test]
    fn offline_proof_verifies_and_pins() {
        struct Yes;
        impl ProofVerifier for Yes {
            fn verify(&self, c: &Claim, now: u64) -> Option<ProvenRecord> {
                assert_eq!(now, NOW, "signatures are checked at the decision's time");
                // Author 2's proof shows the record naming 2 and 4, signed
                // at 100; author 5's an older one naming only 5.
                match c.author {
                    a if a == npub(2) || a == npub(4) => Some(ProvenRecord {
                        signed_at: 100,
                        named: vec![npub(2), npub(4)],
                    }),
                    a if a == npub(5) => Some(ProvenRecord {
                        signed_at: 50,
                        named: vec![npub(5)],
                    }),
                    _ => None,
                }
            }
        }
        let mut proven = claim(2, 5);
        proven.dnssec = Some("AAAA".into());
        let o = decide(Input {
            domain: "example.org",
            pins: vec![],
            txt: TxtLookup::Unreachable,
            claims: &[claim(3, 9), proven],
            now: NOW,
            allow_unverified_offline: false,
            proofs: &Yes,
        });
        let b = &bound(&o)[0];
        assert_eq!((b.npub, b.method), (npub(2), Method::Dnssec));
        assert_eq!(o.changes, vec![PinChange::Put(b.clone())]);
        // Every proven claim is a server, newest first; an unproven one is not.
        let mut second = claim(4, 7);
        second.dnssec = Some("AAAA".into());
        let mut first = claim(2, 5);
        first.dnssec = Some("AAAA".into());
        let o = decide(Input {
            domain: "example.org",
            pins: vec![],
            txt: TxtLookup::Unreachable,
            claims: &[first, claim(3, 9), second],
            now: NOW,
            allow_unverified_offline: false,
            proofs: &Yes,
        });
        assert_eq!(npubs(&o), vec![npub(4), npub(2)]);
        assert_eq!(o.changes.len(), 2);
        // A retired key whose claim carries an older, still valid proof is
        // not a server: the newer record no longer names it.
        let mut retired = claim(5, 20);
        retired.dnssec = Some("AAAA".into());
        let mut current = claim(2, 5);
        current.dnssec = Some("AAAA".into());
        let o = decide(Input {
            domain: "example.org",
            pins: vec![],
            txt: TxtLookup::Unreachable,
            claims: &[retired, current],
            now: NOW,
            allow_unverified_offline: false,
            proofs: &Yes,
        });
        assert_eq!(npubs(&o), vec![npub(2)]);
        // Already pinned to the retired key from its older proof (evidence
        // signed at 50): the newer record retires it and brings in 2.
        let mut retired_pin = pin(5, Method::Dnssec);
        retired_pin.verified_at = 50;
        let mut current = claim(2, 5);
        current.dnssec = Some("AAAA".into());
        let o = decide(Input {
            domain: "example.org",
            pins: vec![retired_pin.clone()],
            txt: TxtLookup::Unreachable,
            claims: &[claim(5, 20), current.clone()],
            now: NOW,
            allow_unverified_offline: false,
            proofs: &Yes,
        });
        assert_eq!(npubs(&o), vec![npub(2)]);
        assert!(o.changes.contains(&PinChange::Forget(npub(5))));
        assert_eq!(bound(&o)[0].verified_at, 100, "the evidence's age");
        // A pin verified online after that record was signed stays.
        retired_pin.verified_at = 150;
        let o = decide(Input {
            domain: "example.org",
            pins: vec![retired_pin],
            txt: TxtLookup::Unreachable,
            claims: &[claim(5, 20), current],
            now: NOW,
            allow_unverified_offline: false,
            proofs: &Yes,
        });
        assert_eq!(npubs(&o), vec![npub(5), npub(2)]);
    }

    #[test]
    fn proofs_of_different_records_signed_at_once_conflict() {
        // Signers that align inception (PowerDNS: the start of the week)
        // give two versions of the record the same time: refuse, rather
        // than let the relay's order pick.
        struct Tie;
        impl ProofVerifier for Tie {
            fn verify(&self, c: &Claim, _: u64) -> Option<ProvenRecord> {
                Some(ProvenRecord {
                    signed_at: 100,
                    named: vec![c.author],
                })
            }
        }
        let (mut a, mut b) = (claim(1, 5), claim(2, 6));
        a.dnssec = Some("AAAA".into());
        b.dnssec = Some("AAAA".into());
        let o = decide(Input {
            domain: "example.org",
            pins: vec![],
            txt: TxtLookup::Unreachable,
            claims: &[a, b],
            now: NOW,
            allow_unverified_offline: true,
            proofs: &Tie,
        });
        assert_eq!(o.decision, Decision::NotOverFips(Reason::Conflict));
    }

    #[test]
    fn public_suffix_is_never_bound() {
        let o = decide(Input {
            domain: "ch",
            pins: vec![],
            txt: txt(&[1], Method::Dnssec),
            claims: &[],
            now: NOW,
            allow_unverified_offline: true,
            proofs: &NoProofs,
        });
        assert_eq!(o.decision, Decision::NotOverFips(Reason::PublicSuffix));
    }

    #[test]
    fn ingest_zone_takes_the_servers_newest_and_ignores_others() {
        use crate::claim::Target;
        let store = MemoryPinStore::new();
        let ev = |author: u8, created_at: u64, target: u8| Event {
            kind: crate::KIND_ZONE,
            pubkey: npub(author).to_hex(),
            created_at,
            tags: ZoneRecord::tags("example.org", &[("git".into(), Target::Node(npub(target)))]),
        };
        let z = ingest_zone(
            &store,
            "example.org",
            npub(1),
            &[ev(1, 10, 2), ev(1, 20, 3), ev(9, 99, 4)],
            NOW,
        )
        .unwrap();
        assert_eq!(
            z.lookup("git"),
            Some(npub(3)),
            "newest by the server; a stranger's record is ignored"
        );
        assert!(
            ingest_zone(&store, "example.org", npub(1), &[ev(1, 15, 5)], NOW).is_none(),
            "rollback"
        );
        assert!(
            ingest_zone(&store, "example.org", npub(1), &[ev(1, NOW + 3600, 5)], NOW).is_none(),
            "future"
        );
    }

    #[test]
    fn ingest_filters_future_rollback_and_duplicates() {
        let store = MemoryPinStore::new();
        let hex = |b: u8| npub(b).to_hex();
        let ev = |author: u8, created_at: u64| Event {
            kind: KIND_CLAIM,
            pubkey: hex(author),
            created_at,
            tags: Claim::tags("example.org", 5355, None),
        };
        let first = ingest_claims(
            &store,
            "example.org",
            &[ev(1, 100), ev(1, 90), ev(2, 50)],
            NOW,
        );
        assert_eq!(first.len(), 2);
        assert_eq!(
            first
                .iter()
                .find(|c| c.author == npub(1))
                .unwrap()
                .created_at,
            100
        );
        // A relay now withholds the newer event: the older one is ignored.
        let again = ingest_claims(&store, "example.org", &[ev(1, 90)], NOW);
        assert!(again.is_empty(), "rollback");
        // Future-dated and foreign-domain events are dropped.
        let mut foreign = ev(3, 10);
        foreign.tags[0][1] = "other.org".into();
        let x = ingest_claims(&store, "example.org", &[ev(3, NOW + 3600), foreign], NOW);
        assert!(x.is_empty());
    }
}
