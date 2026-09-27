# Resolving public domain names over fips

Status: **draft design**, no implementation yet.

A fips node — with or without Internet access — resolves a public name such
as `www.example.org` to the npub of the fips node that serves it, and reaches
it over the mesh. Nostr is the discovery channel, the mesh carries the lookup
of individual names, and legacy DNS is used at most as an optional verifier.

## 1. Goals and non-goals

Goals:

- Resolve public-looking names (`www.example.org`) to fips npubs for any
  application on a fips machine — including browsers, which are never changed.
- Keep working with **no legacy DNS reachable** (Internet down, mesh-only
  network, censorship).
- Use legacy DNS **only for verification**, never as a requirement.
- Never let a name resolve to a party that merely claimed it.

Non-goals:

- Replacing ICANN or creating a global, consensus-based registry. There is no
  global agreement on names in Nostr or fips; this design works with bindings
  that are verified or trusted, and refuses the rest.
- Making names resolvable for machines without fips. They cannot reach `fd…`
  addresses anyway.
- Transport security for applications. fips encrypts end to end and
  authenticates the far npub; TLS is optional (see §8, HSTS).

## 2. Flow overview

```
client resolver                         Nostr relays        legacy DNS        npubxyz (domain's fips DNS server)
      │  1. claim for example.org? ───────────▶│
      │◀──────── claim: npubxyz, port 53 ──────│
      │  2. _fips-dns._udp.example.org SRV? ───────────────────────▶│     (optional; skipped when unreachable)
      │◀──────────────────── npubxyz.fips:53 ────────────────────────│
      │  3. www.example.org? (DNS over UDP, over the mesh) ─────────────────────────────▶│
      │◀────────────────────────────── CNAME npub1234.fips. ─────────────────────────────│
      ▼
   synthesize AAAA = fd… address of npub1234, return to the application
```

The **binding** (domain → server npub) is established in steps 1–2. The
**records** under the domain come from that server in step 3, authenticated
by the mesh: only `npubxyz` can send from `npubxyz`'s fips address.

## 3. Nostr events

All events are signed with the node's identity key — in fips the Nostr key
*is* the mesh identity, so an event authored by `npubX` is authentic for mesh
node `npubX`. Kind numbers sit next to fips's own (`37195` overlay advert,
`21059` signal); they are placeholders until registered.

### 3.1 Claim — kind 37197 (addressable)

Published by the server that serves a domain.

```jsonc
{
  "kind": 37197,
  "pubkey": "<npubxyz hex>",
  "tags": [
    ["d", "example.org"],
    ["port", "53"],
    ["dnssec", "<base64 RFC 9102-style chain for the _fips-dns SRV RRset>"]   // optional
  ],
  "content": ""
}
```

- `d` is the lowercase domain, no trailing dot. One claim per (domain, author).
- The **author must be the server** the claim names. This proves the server
  agreed to serve the domain; it does **not** prove domain ownership.
- Clients query `{"kinds":[37197], "#d":["example.org"]}` and may receive
  claims from several authors (§5.3).

### 3.2 Attestation — kind 37198 (addressable)

Published by a node that verified a binding while it had Internet access.

```jsonc
{
  "kind": 37198,
  "pubkey": "<witness hex>",
  "tags": [
    ["d", "example.org"],
    ["p", "<npubxyz hex>"],
    ["method", "dnssec"],          // or "dns" (unsigned DNS, several resolvers)
    ["verified_at", "<unix time>"]
  ],
  "content": ""
}
```

An attestation is only worth the trust the reader places in the witness.

### 3.3 Zone record — kind 37199 (addressable)

Published by the server: the names it would answer in step 3, so clients can
resolve while the server itself is offline.

```jsonc
{
  "kind": 37199,
  "pubkey": "<npubxyz hex>",
  "tags": [
    ["d", "example.org"],
    ["name", "www", "<npub1234 hex>"],
    ["name", "git", "<npub5678 hex>"],
    ["name", "*",   "self"]
  ],
  "content": ""
}
```

Authentic by signature; freshness by `created_at` (§8, rollback). At most 256
`name` tags; labels follow the hostname rules (letters, digits, hyphens, ≤ 63
characters, no label starting with `npub1`).

## 4. Legacy DNS records (optional verifier)

```
_fips-dns._udp.example.org.  SRV  0 0 53  npub1xyz…(63 chars).fips.
```

- An npub is exactly 63 characters, the maximum length of one DNS label, so
  `npub….fips.` is a valid SRV target.
- A matching SRV record verifies the claim. With **DNSSEC** it is
  cryptographically strong; without it, it is only as strong as the client's
  DNS path — query two or three independent resolvers.
- The same RRset, with its DNSSEC chain serialized into the claim's `dnssec`
  tag, lets anyone verify the binding **offline** against the DNS root key.

## 5. Resolver

### 5.1 Precedence

For a name `N` asked by an application:

1. **Local names** — the user's hosts file (and names synced from a trusted
   node). Always win.
2. **Verified or pinned binding** for the domain of `N`: verified by this
   node (DNSSEC, or matching unsigned DNS from several resolvers), or pinned
   from an earlier verification.
3. **DNSSEC proof in the claim**, verified locally against the root key.
4. **Attested** by at least *k* witnesses the user trusts (k configurable,
   default 2).
5. **Unverified** — refused (NXDOMAIN) by default; optionally resolved with an
   explicit "unverified" marker in logs/UI. Never silently.

If no binding exists at all, the name is forwarded to the legacy upstream as
today — non-participating domains behave exactly as before.

### 5.2 Which domain is "the domain of N"

Walk `N` from the right: `www.example.org` → try `example.org`, then
`www.example.org` (longest claim wins). Public-suffix-aware: never accept a
claim for a public suffix (`ch`, `co.uk`) — use a bundled Public Suffix List.

### 5.3 Several claims for one domain

- Keep only claims whose author is also the SRV target (when DNS was
  reachable) — this resolves all conflicts online.
- Offline: a pinned binding wins; otherwise the claim with a valid DNSSEC
  proof; otherwise the claim with the most trusted attestations. Ties or no
  evidence → treat as unverified (§5.1 step 5).

### 5.4 Pinning

- A binding verified once is pinned (domain → npub, verified_at, method).
- A **changed** binding is accepted only through a fresh verification of
  equal or stronger method (DNSSEC ≥ multi-resolver DNS ≥ attestation). A
  pinned binding is never replaced by an unverified claim.

### 5.5 Caching

| Item | TTL |
|---|---|
| Legacy SRV miss (no binding) | 6 h — most domains have none |
| Legacy SRV hit | min(SRV TTL, 1 h) |
| Claim / attestation fetched from relays | 1 h, stale-while-revalidate |
| Step 3 answer | its TTL, capped at 1 h |
| Answer synthesized for an application | 30 s — so a lost mesh route falls back quickly |

## 6. Step 3 wire protocol

- Plain DNS over **UDP** to `[fd… of npubxyz]:<port>` (default 53), over the
  mesh. UDP is sufficient: fips authenticates the source address, so the
  spoofing problem that motivates TCP on the Internet does not exist, and UDP
  saves a round trip. Answers are small — far below the mesh's effective IPv6
  MTU (~1200 bytes; EDNS0 buffer 1232).
- **TCP fallback** when an answer comes back truncated (TC bit); servers must
  support both, as RFC 7766 requires of DNS.
- Answer format: **`CNAME npub….fips.`** (plus optionally the synthesized
  AAAA). The npub must travel, not just an address: a fips node can only route
  to an `fd…` address whose identity it knows, and resolving `npub….fips`
  locally is what registers it.
- Unknown name → NXDOMAIN. `*` in the zone → the server's own npub.
- Server offline → fall back to the zone record (§3.3).

## 7. OS integration

Browsers never ask for SRV and are never changed. The machine's resolver is:

- **Phone (fips2go):** the shim already intercepts all DNS from captured
  apps; the hook is the non-`.fips` branch of `DnsProxy::serve`
  (`shim/src/dns.rs`), which forwards to upstreams today.
- **Linux/macOS:** a local forwarding resolver for *all* names (standalone, or
  inside the fips daemon), wired in via systemd-resolved (`~.` routing domain
  on the fips link) or as dnsmasq/unbound upstream.

For a name with a binding and a reachable npub, the resolver:

- answers AAAA with the synthesized `fd…` address,
- answers A with NODATA and **suppresses the public AAAA** — address sorting
  (RFC 6724, used by bionic, glibc and Chromium) ranks `fd00::/8` below both
  IPv4 and global IPv6, so returning both would almost never use the mesh,
- falls back to the legacy answer on any failure (timeout, parse error, no
  route). A bug must never make a public domain unreachable.

Known holes:

- Browsers with their own encrypted DNS (Firefox TRR, Chrome "secure DNS with
  a provider") bypass the system resolver. Answering the canary
  `use-application-dns.net` with NXDOMAIN disables Firefox's automatic DoH;
  enterprise policies can still override.
- IPv4-only applications only ask for A records and keep using the legacy
  Internet.

## 8. Security and privacy

- **Squatting:** anyone can publish a claim for any domain. Only §5.1 steps
  1–4 resolve; unverified claims are refused.
- **Transport:** fips authenticates the far npub end to end, so the security
  of a lookup equals the security of the binding. Without TLS a wrong binding
  means talking securely to the wrong party — hence strict precedence.
- **HSTS / secure contexts:** a browser that has HSTS stored for the name, or
  a page needing a secure context, still requires `https://`. A server using
  the same name on both networks should serve its certificate on its fips
  address too.
- **DNS spoofing without DNSSEC:** an attacker on the client's DNS path could
  publish a claim and forge the matching SRV answer. Multiple independent
  resolvers and pinning reduce this; DNSSEC removes it.
- **Rollback / withholding:** relays can hide a newer event but cannot forge
  one. Keep and persist the highest `created_at` seen per (kind, author, d);
  ignore timestamps more than 10 minutes in the future.
- **Privacy — browsing history:** asking relays about every visited domain
  gives relay operators the browsing history. When online, check the legacy
  `_fips-dns` SRV first (that upstream already sees the name) and query relays
  only for domains with an SRV hint, when offline, or against a locally synced
  claim set. Step 3 reveals the name only to the domain's own server.
- **Limits:** event size, tag counts, label rules and a public-suffix check
  are enforced before anything is cached.

## 9. Phasing

1. **MVP:** claim (§3.1) + SRV verification + pinning + step 3 over UDP with
   CNAME; unverified refused; phone integration in the fips2go shim.
2. **Attestations** (§3.2) and the trust setting *k*; zone records (§3.3) for
   offline servers.
3. **DNSSEC proofs** in claims — fully trustless offline verification.
4. Desktop resolver (Linux first).

## 10. Open questions

- Final kind numbers (registration with the Nostr NIP process).
- Where the desktop resolver lives: standalone daemon vs. inside fips.
- Whether witnesses should be the user's fips-ui-synced trusted nodes by
  default.
- Relay selection for claims: fips's relay pool, or a dedicated set.
