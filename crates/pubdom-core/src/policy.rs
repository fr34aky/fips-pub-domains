//! The verification precedence (spec §5.1), conflict rules (§5.3), pin
//! changes (§5.4) and the offline path (§5.5), as one pure function over
//! what the resolver gathered.
//!
//! "Refused" applies to the *binding*, never to the name: every negative
//! outcome is [`Decision::NotOverFips`], which the resolver turns into a
//! legacy passthrough when online and into the ordinary offline failure
//! otherwise (spec §5.1, §7).

use crate::claim::{Claim, Event, ZoneRecord};
use crate::domain::is_claimable;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Resolve over the mesh through this binding.
    Bound(Binding),
    /// Resolve, but only because the user opted into unverified offline
    /// bindings; must be surfaced as such (spec §5.1 step 5).
    Unverified(Binding),
    NotOverFips(Reason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinUpdate {
    Keep,
    Put(Binding),
    Forget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    pub pin_update: PinUpdate,
}

/// Verifies the `dnssec` proof carried in a claim against the DNS root
/// trust anchor (phase 2). Phase 1 passes [`NoProofs`].
pub trait ProofVerifier {
    /// `true` if the claim's proof shows a `_fips-dns` TXT record naming the
    /// claim's author, and it validates.
    fn verify(&self, claim: &Claim) -> bool;
}

pub struct NoProofs;
impl ProofVerifier for NoProofs {
    fn verify(&self, _: &Claim) -> bool {
        false
    }
}

pub struct Input<'a> {
    pub domain: &'a str,
    pub pin: Option<Binding>,
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
        pin_update: PinUpdate::Keep,
    };

    if !is_claimable(input.domain) {
        return keep(Decision::NotOverFips(Reason::PublicSuffix));
    }

    match &input.txt {
        TxtLookup::Hit { records, method } => {
            let named: Vec<_> = records.iter().map(|r| r.npub).collect();
            let mut matching: Vec<&Claim> = input
                .claims
                .iter()
                .filter(|c| named.contains(&c.author))
                .collect();
            if matching.is_empty() {
                // DNS says the domain participates but no reachable relay
                // carries the claim. If we are pinned to a key the record
                // still names, the pin resolves (spec §5.1 step 2): the claim
                // was verified when the pin was made, and the record vouches
                // for the same server today. Otherwise not over fips, and the
                // pin, if any, stays.
                if let Some(pin) = &input.pin
                    && named.contains(&pin.npub)
                {
                    return keep(Decision::Bound(pin.clone()));
                }
                let reason = if input.claims.is_empty() {
                    Reason::NoClaim
                } else {
                    Reason::ClaimMismatch
                };
                return keep(Decision::NotOverFips(reason));
            }
            // Prefer the author we are already pinned to, then the newest.
            let pinned = input.pin.as_ref().map(|p| p.npub);
            matching.sort_by(|a, b| {
                let ap = Some(a.author) == pinned;
                let bp = Some(b.author) == pinned;
                bp.cmp(&ap).then(b.created_at.cmp(&a.created_at))
            });
            let chosen = matching[0];
            let fresh = Binding {
                domain: input.domain.to_owned(),
                npub: chosen.author,
                port: chosen.port,
                method: *method,
                verified_at: input.now,
            };
            if let Some(pin) = &input.pin
                && *method < pin.method
            {
                // Weaker than what the pin rests on (spec §5.4): a changed
                // binding is not accepted, and the same binding is not
                // downgraded either — else an unsigned replay of the real
                // record would lower the bar for the change that follows.
                return keep(Decision::Bound(pin.clone()));
            }
            Outcome {
                decision: Decision::Bound(fresh.clone()),
                pin_update: PinUpdate::Put(fresh),
            }
        }

        TxtLookup::Miss { method } => {
            // The operator withdrew (or never had) the record: the domain is
            // legacy-only now. Forgetting the pin is a binding change, so it
            // takes a denial at least as strong as the pin (a captive
            // portal's NXDOMAIN must not unpin a DNSSEC binding). A weaker
            // denial keeps the pin but does not use it while DNS says no.
            let pin_update = match &input.pin {
                Some(pin) if *method >= pin.method => PinUpdate::Forget,
                _ => PinUpdate::Keep,
            };
            Outcome {
                decision: Decision::NotOverFips(Reason::NoTxt),
                pin_update,
            }
        }

        TxtLookup::Unreachable => {
            if let Some(pin) = &input.pin {
                return keep(Decision::Bound(pin.clone()));
            }
            // Offline and unpinned: only a proof carried in the claim can
            // verify it (spec §5.5).
            if let Some(proven) = input
                .claims
                .iter()
                .filter(|c| c.dnssec.is_some() && input.proofs.verify(c))
                .max_by_key(|c| c.created_at)
            {
                let b = Binding {
                    domain: input.domain.to_owned(),
                    npub: proven.author,
                    port: proven.port,
                    method: Method::Dnssec,
                    verified_at: input.now,
                };
                return Outcome {
                    decision: Decision::Bound(b.clone()),
                    pin_update: PinUpdate::Put(b),
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

/// The newest zone record for `domain` by `author` (the pinned server),
/// with the same future and rollback filters as claims (spec §3.3, §8).
/// Records by anyone else are ignored: only the domain's server may say
/// which nodes serve its names.
pub fn ingest_zone(
    store: &dyn PinStore,
    domain: &str,
    author: crate::Npub,
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
    use crate::identity::Npub;
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
    fn run(pin_: Option<Binding>, txt_: TxtLookup, claims: &[Claim], allow: bool) -> Outcome {
        decide(Input {
            domain: "example.org",
            pin: pin_,
            txt: txt_,
            claims,
            now: NOW,
            allow_unverified_offline: allow,
            proofs: &NoProofs,
        })
    }
    fn bound(o: &Outcome) -> &Binding {
        match &o.decision {
            Decision::Bound(b) => b,
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    #[test]
    fn online_hit_with_matching_claim_binds_and_pins() {
        let o = run(None, txt(&[1], Method::Dnssec), &[claim(1, 5)], false);
        let b = bound(&o);
        assert_eq!(
            (b.npub, b.method, b.verified_at),
            (npub(1), Method::Dnssec, NOW)
        );
        assert_eq!(o.pin_update, PinUpdate::Put(b.clone()));
    }

    #[test]
    fn online_hit_without_matching_claim_is_legacy_and_keeps_pin() {
        let o = run(
            Some(pin(1, Method::Dns)),
            txt(&[2], Method::Dns),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::ClaimMismatch));
        assert_eq!(o.pin_update, PinUpdate::Keep);
        let o = run(None, txt(&[2], Method::Dns), &[], false);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoClaim));
    }

    #[test]
    fn pinned_server_still_named_by_txt_resolves_without_a_claim() {
        // Found on the phone: its relays did not carry the claim (it lived on
        // a relay inside the mesh), but the pin plus a TXT naming the same
        // key is a verified binding.
        let o = run(
            Some(pin(1, Method::Dnssec)),
            txt(&[1], Method::Dnssec),
            &[],
            false,
        );
        assert_eq!(bound(&o).npub, npub(1));
        assert_eq!(o.pin_update, PinUpdate::Keep);
        // …but not when the record names someone else.
        let o = run(
            Some(pin(1, Method::Dnssec)),
            txt(&[2], Method::Dnssec),
            &[],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoClaim));
    }

    #[test]
    fn changed_binding_needs_equal_or_stronger_verification() {
        // Pinned via DNSSEC; today's answer is unsigned and names a new key.
        let o = run(
            Some(pin(1, Method::Dnssec)),
            txt(&[2], Method::Dns),
            &[claim(2, 5)],
            false,
        );
        assert_eq!(
            bound(&o).npub,
            npub(1),
            "weaker verification cannot move the pin"
        );
        assert_eq!(o.pin_update, PinUpdate::Keep);
        // Same strength: accepted.
        let o = run(
            Some(pin(1, Method::Dnssec)),
            txt(&[2], Method::Dnssec),
            &[claim(2, 5)],
            false,
        );
        assert_eq!(bound(&o).npub, npub(2));
        assert!(matches!(o.pin_update, PinUpdate::Put(_)));
        // Stronger than the pin: also accepted, and the pin upgrades.
        let o = run(
            Some(pin(1, Method::DnsSingle)),
            txt(&[1], Method::Dnssec),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(bound(&o).method, Method::Dnssec);
    }

    #[test]
    fn same_author_is_never_downgraded() {
        // An unsigned replay of the real record must not lower the pin's
        // method, or the next unsigned answer could move the binding.
        let o = run(
            Some(pin(1, Method::Dnssec)),
            txt(&[1], Method::DnsSingle),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(bound(&o).method, Method::Dnssec);
        assert_eq!(o.pin_update, PinUpdate::Keep);
    }

    #[test]
    fn several_named_servers_prefer_pinned_then_newest() {
        let claims = [claim(1, 5), claim(2, 9)];
        let o = run(None, txt(&[1, 2], Method::Dns), &claims, false);
        assert_eq!(bound(&o).npub, npub(2), "newest claim wins without a pin");
        let o = run(
            Some(pin(1, Method::Dns)),
            txt(&[1, 2], Method::Dns),
            &claims,
            false,
        );
        assert_eq!(bound(&o).npub, npub(1), "the pinned author wins");
    }

    #[test]
    fn txt_miss_forgets_the_pin_only_with_a_denial_as_strong_as_the_pin() {
        let miss = |m| TxtLookup::Miss { method: m };
        let o = run(
            Some(pin(1, Method::Dnssec)),
            miss(Method::Dnssec),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoTxt));
        assert_eq!(o.pin_update, PinUpdate::Forget);
        // A captive portal's unsigned NXDOMAIN: not used, but not forgotten.
        let o = run(
            Some(pin(1, Method::Dnssec)),
            miss(Method::DnsSingle),
            &[claim(1, 5)],
            false,
        );
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoTxt));
        assert_eq!(o.pin_update, PinUpdate::Keep);
        let o = run(Some(pin(1, Method::Dns)), miss(Method::Dns), &[], false);
        assert_eq!(o.pin_update, PinUpdate::Forget);
        let o = run(None, miss(Method::DnsSingle), &[], false);
        assert_eq!(o.pin_update, PinUpdate::Keep);
    }

    #[test]
    fn offline_uses_the_pin_and_refuses_the_rest() {
        let o = run(
            Some(pin(1, Method::Dns)),
            TxtLookup::Unreachable,
            &[claim(2, 5)],
            false,
        );
        assert_eq!(bound(&o).npub, npub(1));
        assert_eq!(o.pin_update, PinUpdate::Keep);
        let o = run(None, TxtLookup::Unreachable, &[claim(2, 5)], false);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::Unverified));
        let o = run(None, TxtLookup::Unreachable, &[], false);
        assert_eq!(o.decision, Decision::NotOverFips(Reason::NoClaim));
    }

    #[test]
    fn offline_opt_in_marks_a_single_claim_and_refuses_conflicts() {
        let o = run(None, TxtLookup::Unreachable, &[claim(2, 5)], true);
        match o.decision {
            Decision::Unverified(b) => {
                assert_eq!((b.npub, b.method), (npub(2), Method::Unverified))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(o.pin_update, PinUpdate::Keep, "unverified is never pinned");
        let o = run(
            None,
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
            fn verify(&self, c: &Claim) -> bool {
                c.author == npub(2)
            }
        }
        let mut proven = claim(2, 5);
        proven.dnssec = Some("AAAA".into());
        let o = decide(Input {
            domain: "example.org",
            pin: None,
            txt: TxtLookup::Unreachable,
            claims: &[claim(3, 9), proven],
            now: NOW,
            allow_unverified_offline: false,
            proofs: &Yes,
        });
        let b = bound(&o);
        assert_eq!((b.npub, b.method), (npub(2), Method::Dnssec));
        assert!(matches!(o.pin_update, PinUpdate::Put(_)));
    }

    #[test]
    fn public_suffix_is_never_bound() {
        let o = decide(Input {
            domain: "ch",
            pin: None,
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
        foreign.tags[0][1] = "other.ch".into();
        let x = ingest_claims(&store, "example.org", &[ev(3, NOW + 3600), foreign], NOW);
        assert!(x.is_empty());
    }
}
