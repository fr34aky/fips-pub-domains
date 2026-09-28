//! Hostname rules and "which domain is the domain of N" (spec §5.2).

use crate::identity::looks_like_npub;

/// Lowercase, strip the trailing dot, and check RFC 1123 hostname syntax
/// (LDH labels of 1–63 characters, no leading/trailing hyphen, ≤ 253 total).
/// Returns `None` for anything an application should never have asked.
pub fn normalize(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if !lower.split('.').all(is_valid_label) {
        return None;
    }
    Some(lower)
}

/// One hostname label. Underscore is allowed only as the first character so
/// that `_fips-dns` itself passes; zone labels additionally must not look
/// like an npub, which fips reserves (spec §3.3).
pub fn is_valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .enumerate()
        .all(|(i, b)| b.is_ascii_alphanumeric() || *b == b'-' || (*b == b'_' && i == 0))
}

/// A label the zone of a domain may define (spec §3.3): a hostname label,
/// `*`, and never an npub.
pub fn is_valid_zone_label(label: &str) -> bool {
    label == "*" || (is_valid_label(label) && !label.starts_with('_') && !looks_like_npub(label))
}

/// The registrable domain of `name` per the Public Suffix List, or `None`
/// when `name` is itself a public suffix, under an unknown TLD, or malformed.
/// A claim is never accepted for a public suffix (spec §5.2).
pub fn registrable(name: &str) -> Option<String> {
    let name = normalize(name)?;
    let suffix = psl::suffix(name.as_bytes())?;
    if !suffix.is_known() {
        return None;
    }
    let domain = psl::domain(name.as_bytes())?;
    std::str::from_utf8(domain.as_bytes()).ok().map(str::to_owned)
}

/// Is `domain` acceptable as the `d` of a claim: normalized, registrable,
/// and not a public suffix?
pub fn is_claimable(domain: &str) -> bool {
    match (normalize(domain), registrable(domain)) {
        (Some(n), Some(r)) => n.len() >= r.len() && n.ends_with(&r),
        _ => false,
    }
}

/// Domains under which a claim could cover `name`, shortest first:
/// `www.a.example.org` → `[example.org, a.example.org, www.a.example.org]`.
/// The resolver tries the longest claim that exists (spec §5.2).
pub fn candidates(name: &str) -> Vec<String> {
    let Some(name) = normalize(name) else {
        return Vec::new();
    };
    let Some(reg) = registrable(&name) else {
        return Vec::new();
    };
    let mut out = vec![reg.clone()];
    if name.len() > reg.len() {
        let prefix = &name[..name.len() - reg.len() - 1];
        let labels: Vec<&str> = prefix.split('.').collect();
        for i in (0..labels.len()).rev() {
            out.push(format!("{}.{}", labels[i..].join("."), reg));
        }
    }
    out
}

/// The `_fips-dns.<domain>` name that carries the verifier TXT record.
pub fn txt_name(domain: &str) -> String {
    format!("{}.{}", crate::TXT_LABEL, domain)
}

/// The label of `name` relative to `domain`: `www` for
/// (`www.example.org`, `example.org`); `@` for the apex; `None` if unrelated.
pub fn relative_label<'a>(name: &'a str, domain: &str) -> Option<&'a str> {
    if name == domain {
        return Some("@");
    }
    name.strip_suffix(domain)?.strip_suffix('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize("WWW.Example.ORG.").as_deref(), Some("www.example.org"));
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("a..b"), None);
        assert_eq!(normalize("-a.ch"), None);
        assert_eq!(normalize("a_b.ch"), None);
        assert_eq!(normalize("_fips-dns.example.org").as_deref(), Some("_fips-dns.example.org"));
        assert_eq!(normalize(&"a".repeat(64)), None);
    }

    #[test]
    fn registrable_domain_is_psl_aware() {
        assert_eq!(registrable("www.example.org").as_deref(), Some("example.org"));
        assert_eq!(registrable("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        // Private-section suffixes: the user of github.io owns foo.github.io.
        assert_eq!(registrable("x.foo.github.io").as_deref(), Some("foo.github.io"));
        assert_eq!(registrable("ch"), None);
        assert_eq!(registrable("co.uk"), None);
        // Unknown TLDs (.fips, .local, .internal) are never claimable.
        assert_eq!(registrable("home.fips"), None);
        assert_eq!(registrable("printer.local"), None);
    }

    #[test]
    fn claimable_rejects_public_suffixes() {
        assert!(is_claimable("example.org"));
        assert!(is_claimable("Sub.Example.org."));
        assert!(!is_claimable("ch"));
        assert!(!is_claimable("co.uk"));
        assert!(!is_claimable("github.io"));
        assert!(!is_claimable("fips"));
    }

    #[test]
    fn candidates_walk_from_the_registrable_domain() {
        assert_eq!(
            candidates("www.a.example.org"),
            vec!["example.org", "a.example.org", "www.a.example.org"]
        );
        assert_eq!(candidates("example.org"), vec!["example.org"]);
        assert!(candidates("ch").is_empty());
        assert!(candidates("npub1abc.fips").is_empty());
    }

    #[test]
    fn zone_labels() {
        assert!(is_valid_zone_label("www"));
        assert!(is_valid_zone_label("*"));
        assert!(!is_valid_zone_label("_fips-dns"));
        assert!(!is_valid_zone_label(&format!("npub1{}", "q".repeat(58))));
        assert_eq!(relative_label("www.example.org", "example.org"), Some("www"));
        assert_eq!(relative_label("example.org", "example.org"), Some("@"));
        assert_eq!(relative_label("evilexample.org", "example.org"), None);
        assert_eq!(txt_name("example.org"), "_fips-dns.example.org");
    }
}
