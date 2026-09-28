//! Nostr public keys as fips identities.
//!
//! fips derives a node's mesh address from its x-only secp256k1 public key:
//! `fd` followed by the first 15 bytes of SHA-256(pubkey) (fips
//! `src/identity/{node_addr,address}.rs`). The same key, bech32-encoded with
//! the `npub` prefix (NIP-19), is the Nostr author of the node's events and
//! the label of its `<npub>.fips` name. This module does that arithmetic
//! without depending on the fips crate.

use bech32::{Bech32, Hrp};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv6Addr;

/// An x-only public key: a fips node identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Npub([u8; 32]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NpubError {
    #[error("not a bech32 string")]
    Bech32,
    #[error("wrong prefix: expected npub")]
    Prefix,
    #[error("wrong key length: expected 32 bytes, got {0}")]
    Length(usize),
    #[error("not a 64-character hex string")]
    Hex,
}

impl Npub {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse the bech32 `npub1…` form.
    pub fn parse(s: &str) -> Result<Self, NpubError> {
        let (hrp, data) = bech32::decode(s).map_err(|_| NpubError::Bech32)?;
        if hrp.as_str() != "npub" {
            return Err(NpubError::Prefix);
        }
        let bytes: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| NpubError::Length(data.len()))?;
        Ok(Self(bytes))
    }

    /// Parse the 64-character hex form used in event `pubkey` and `p` tags.
    pub fn from_hex(s: &str) -> Result<Self, NpubError> {
        if s.len() != 64 {
            return Err(NpubError::Hex);
        }
        let v = hex::decode(s).map_err(|_| NpubError::Hex)?;
        let bytes: [u8; 32] = v.as_slice().try_into().map_err(|_| NpubError::Hex)?;
        Ok(Self(bytes))
    }

    /// Either form; what a user or a TXT record might hand us.
    pub fn parse_any(s: &str) -> Result<Self, NpubError> {
        if s.starts_with("npub1") {
            Self::parse(s)
        } else {
            Self::from_hex(s)
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The node's mesh address: `fd` + SHA-256(pubkey)[0..15].
    pub fn fips_address(&self) -> Ipv6Addr {
        let digest = Sha256::digest(self.0);
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[1..].copy_from_slice(&digest[..15]);
        Ipv6Addr::from(addr)
    }

    /// The `<npub>.fips` name that fips's own responder resolves — asking it
    /// for this name is what registers the identity for routing (spec §6).
    pub fn fips_name(&self) -> String {
        format!("{self}.fips")
    }
}

impl fmt::Display for Npub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse("npub").expect("static hrp");
        let s = bech32::encode::<Bech32>(hrp, &self.0).expect("32 bytes encode");
        f.write_str(&s)
    }
}

impl fmt::Debug for Npub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Npub({self})")
    }
}

impl std::str::FromStr for Npub {
    type Err = NpubError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_any(s)
    }
}

impl serde::Serialize for Npub {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Npub {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_any(&s).map_err(serde::de::Error::custom)
    }
}

/// Is `label` (the part before `.fips`) an npub rather than a hostname?
/// fips reserves that form; zone labels may not start with it (spec §3.3).
pub fn looks_like_npub(label: &str) -> bool {
    label.len() == 63 && label.starts_with("npub1")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The demo domain's server (docs/testing.md).
    const DEMO: &str = "npub1uyutnt7z78e7rpjx4dtkms2ukfs6kkq0feeqa5jqllnylmrpjkqs35ysdl";

    #[test]
    fn npub_round_trips_through_bech32_and_hex() {
        let n = Npub::parse(DEMO).unwrap();
        assert_eq!(n.to_string(), DEMO);
        assert_eq!(Npub::from_hex(&n.to_hex()).unwrap(), n);
        assert_eq!(Npub::parse_any(&n.to_hex()).unwrap(), n);
        assert_eq!(
            DEMO.len(),
            63,
            "an npub is exactly one max-length DNS label"
        );
    }

    #[test]
    fn address_matches_fips_derivation() {
        // fd + first 15 bytes of sha256(x-only key); cross-checked against
        // fips's FipsAddress::from_node_addr(NodeAddr::from_pubkey(..)).
        let n = Npub::from_bytes([7u8; 32]);
        let digest = Sha256::digest([7u8; 32]);
        let a = n.fips_address().octets();
        assert_eq!(a[0], 0xfd);
        assert_eq!(&a[1..], &digest[..15]);
        assert!(n.fips_name().ends_with(".fips"));
    }

    #[test]
    fn rejects_wrong_prefix_and_garbage() {
        assert_eq!(Npub::parse("nsec1abc").unwrap_err(), NpubError::Bech32);
        assert!(Npub::parse("hello").is_err());
        assert_eq!(Npub::from_hex("abc").unwrap_err(), NpubError::Hex);
        assert!(looks_like_npub(DEMO));
        assert!(!looks_like_npub("www"));
    }
}
