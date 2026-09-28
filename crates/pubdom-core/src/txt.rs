//! The legacy DNS verifier record (spec §4):
//!
//! ```text
//! _fips-dns.example.org.  TXT  "v=fips1 npub=npub1… port=5355"
//! ```
//!
//! Space-separated `key=value` pairs, `v=fips1` first, `npub` required,
//! `port` optional, unknown keys ignored. Several records may name several
//! servers; each parses on its own.

use crate::identity::Npub;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    pub npub: Npub,
    pub port: Option<u16>,
}

impl TxtRecord {
    /// Parse one TXT record's text (the character-strings already joined).
    /// Returns `None` for anything that is not ours — other TXT records may
    /// legitimately sit at the same name.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split_ascii_whitespace();
        if parts.next()? != "v=fips1" {
            return None;
        }
        let mut npub = None;
        let mut port = None;
        for kv in parts {
            let (k, v) = kv.split_once('=')?;
            match k {
                "npub" => npub = Some(Npub::parse_any(v).ok()?),
                "port" => port = Some(v.parse::<u16>().ok().filter(|p| *p != 0)?),
                _ => {}
            }
        }
        Some(Self { npub: npub?, port })
    }

    /// The text of a record that would parse back to `self`, for operators
    /// (`fips-pubdom-server` prints it) and tests.
    pub fn render(&self) -> String {
        match self.port {
            Some(p) => format!("v=fips1 npub={} port={}", self.npub, p),
            None => format!("v=fips1 npub={}", self.npub),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = "npub1uyutnt7z78e7rpjx4dtkms2ukfs6kkq0feeqa5jqllnylmrpjkqs35ysdl";

    #[test]
    fn parses_the_record_as_deployed() {
        let r = TxtRecord::parse(&format!("v=fips1 npub={DEMO} port=5355")).unwrap();
        assert_eq!(r.npub, Npub::parse(DEMO).unwrap());
        assert_eq!(r.port, Some(5355));
        assert_eq!(r.render(), format!("v=fips1 npub={DEMO} port=5355"));
    }

    #[test]
    fn tolerates_order_spacing_unknown_keys_and_hex() {
        let hex = Npub::parse(DEMO).unwrap().to_hex();
        let r = TxtRecord::parse(&format!("v=fips1   future=1 port=53 npub={hex}")).unwrap();
        assert_eq!(r.port, Some(53));
        assert_eq!(
            TxtRecord::parse(&format!("v=fips1 npub={DEMO}"))
                .unwrap()
                .port,
            None
        );
    }

    #[test]
    fn rejects_foreign_or_broken_records() {
        assert_eq!(TxtRecord::parse("v=spf1 -all"), None);
        assert_eq!(
            TxtRecord::parse(&format!("npub={DEMO} v=fips1")),
            None,
            "version first"
        );
        assert_eq!(TxtRecord::parse("v=fips1 port=5355"), None, "npub required");
        assert_eq!(
            TxtRecord::parse(&format!("v=fips1 npub={DEMO} port=0")),
            None
        );
        assert_eq!(
            TxtRecord::parse(&format!("v=fips1 npub={DEMO} port=abc")),
            None
        );
        assert_eq!(TxtRecord::parse("v=fips1 npub=npub1nope"), None);
        assert_eq!(TxtRecord::parse(""), None);
    }
}
