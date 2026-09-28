# Specification: public domain names over fips

Status: phase 1 (§9) is implemented and tested; kind numbers are
placeholders until registered ([nip.md](nip.md)).

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
      │◀──────── claim: npubxyz, port 5355 ────│
      │  2. _fips-dns.example.org TXT? ────────────────────────────▶│     (optional; skipped when unreachable)
      │◀──────────── "v=fips1 npub=npubxyz port=5355" ───────────────│
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
`21059` signal); 37195–37199 are unregistered in the NIPs kind table and in
`nostr-protocol/registry-of-kinds`, and no existing NIP covers domain →
pubkey service bindings (NIP-05 is the reverse direction, over HTTPS). The
NIP draft is [nip.md](nip.md); the tag names below follow it.

### 3.1 Claim — kind 37197 (addressable)

Published by the server that serves a domain.

```jsonc
{
  "kind": 37197,
  "pubkey": "<npubxyz hex>",
  "tags": [
    ["d", "example.org"],
    ["service", "fips-dns", "5355"],
    ["dnssec", "<base64 RFC 9102-style chain for the _fips-dns TXT RRset>"]   // optional
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
_fips-dns.example.org.  TXT  "v=fips1 npub=npub1xyz… port=5355"
```

- A **TXT** record, not SRV: an SRV target must be a hostname, and domain
  hosters validate it (in-zone, resolvable, known TLD) — `npub….fips.` is
  rejected by common control panels. TXT under a `_`-prefixed name is what
  ACME DNS-01, DKIM and site-verification use for the same reason: every
  hoster can set it, and the npub is data, not a name.
- Format: space-separated `key=value` pairs; `v=fips1` first, `npub`
  required, `port` optional (default 5355; the claim's `service` tag is
  authoritative). Unknown keys are ignored. Several TXT records may name
  several servers.
- A TXT record naming the claim's author verifies the claim. With
  **DNSSEC** it is cryptographically strong; without it, it is only as
  strong as the client's DNS path — query two or three independent
  resolvers.
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
5. **Unverified** — the *binding* is refused by default; optionally used
   with an explicit "unverified" marker in logs/UI. Never silently.

"Refused" applies to the binding, never to the name: a refused or missing
binding means the name is **forwarded to the legacy upstream** exactly as
today (§7, "not over fips"). Only offline, with no upstream to forward to,
does the application see a failure — and that is the same failure any
offline machine sees. Non-participating domains therefore behave exactly
as before.

### 5.2 Which domain is "the domain of N"

Walk `N` from the right: `www.example.org` → try `example.org`, then
`www.example.org` (longest claim wins). Public-suffix-aware: never accept a
claim for a public suffix (`ch`, `co.uk`) — use a bundled Public Suffix List.

### 5.3 Several claims for one domain: redundant servers

- Every key the TXT record names and that claims the domain is a
  **server** of the domain — not a conflict. A domain gets redundancy by
  publishing several TXT records and running the server on several nodes
  with the same zone; each node publishes its own claim and zone record.
- The client keeps all of them pinned, in the order they were first
  pinned; the first is the primary. Step 3 asks the servers in that order
  and fails over to the next when one does not answer (§6); a server that
  failed is skipped for a backoff window (5 minutes, tripling per
  consecutive failure, at most 3 hours) and tried again when it expires.
  Zone records (§3.3) from any of the servers are accepted, newest first.
- Claims whose author the record does *not* name are ignored (online).
  Offline: the pinned servers; otherwise the claim with a valid DNSSEC
  proof; otherwise the claim with the most trusted attestations. Ties or
  no evidence → treat as unverified (§5.1 step 5).

### 5.4 Pinning

- A binding verified once is pinned (domain → npub, verified_at, method).
  `verified_at` is when the binding took its current form; re-verifying an
  unchanged binding does not rewrite the pin.
- A **changed** binding is accepted only through a fresh verification of
  equal or stronger method (DNSSEC ≥ multi-resolver DNS ≥ single-resolver
  DNS ≥ attestation). A pinned binding is never replaced by an unverified
  claim.
- The **same** binding re-verified with a weaker method keeps the pin's
  method: an unsigned replay of the real record must not lower the bar for
  the change that follows.
- **Forgetting** a pin (the TXT record is gone, or no longer names that
  server) is a binding change too and takes a denial at least as strong as
  the pin: a DNSSEC-validated denial, or as many agreeing resolvers as
  verified the pin. A weaker denial — a captive portal's NXDOMAIN — leaves
  the pin in place but unused while DNS says no; it resolves again offline
  or once DNS answers properly. With several servers the rule applies per
  server, and it applies whether or not the claim of the server the record
  names instead reached us — else a retired key would stay pinned and
  answer the next offline lookup.
- **Resolvers that disagree** on the record: the answer most of them gave
  counts; a tie between different answers is no answer (as if DNS were
  unreachable, so the pins decide) unless exactly one side validated under
  DNSSEC — list order must never choose between an honest and a poisoned
  resolver.

### 5.5 No public Internet: the claim *is* the TXT record

When no legacy upstream is reachable — the daemon's online flag is off, or
every upstream times out or SERVFAILs on the TXT query — the resolver skips
step 2 and fetches the claim (kind 37197) from relays **directly**: the
claim carries the same information as the TXT record (server npub, port),
so it replaces it. Relays consulted offline are whatever is reachable:

- **mesh relays** — Nostr relays running on fips nodes, configured as
  `ws://<npub>.fips:<port>` (resolving the name through fips's responder is
  what registers the relay's identity; an `[fd…]` literal is not usable
  with nostr-sdk), reachable through the node's TUN like any mesh service. They are configured, or synced from trusted nodes alongside the
  mesh names. The node serving a domain is the natural place to run one
  (it then hosts its own claim), and community nodes can mirror claims.
- the node's public relays, in case they happen to be reachable through
  some other path (e.g. the mesh has a gateway).

Verification offline follows §5.1 without step 2's DNS: pinned > DNSSEC
proof in the claim > attestations > unverified. In phase 1 only pins exist,
so a domain **never seen online is refused offline** unless the user
enabled `allow_unverified_offline`, which resolves it with a visible
"unverified" marker (§5.1 step 5, never silent). Because this is the path
the mesh-only use case depends on, DNSSEC proofs in claims (the only
trustless offline verification) move ahead of attestations in §9.

Privacy differs offline: the relays asked do see the domain. Mesh relays
are run by nodes the user chose, and no public relay is reachable anyway,
so this is accepted; the online rule (TXT first, §8) is unchanged.

### 5.6 Caching

| Item | TTL |
|---|---|
| Legacy TXT miss (no binding) | 6 h — most domains have none |
| Relay miss offline (no claim) | 1 h — so background queries of an offline browser reach mesh relays once per domain, not per query |
| Legacy TXT hit | min(TXT TTL, 1 h) |
| Claim / attestation fetched from relays | 1 h, stale-while-revalidate |
| Step 3 answer | its TTL, capped at 1 h |
| Answer synthesized for an application | 30 s — so a lost mesh route falls back quickly |

## 6. Step 3 wire protocol

- Plain DNS over **UDP** to `[fd… of npubxyz]:<port>` (default 5355), over the
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
- Unknown name → NXDOMAIN, meaning **"not over fips"**: the resolver then
  forwards the name to the legacy upstream (§7); it never passes that
  NXDOMAIN to the application. `*` in the zone → the server's own npub; a
  zone entry with the value `legacy` excludes a name from the wildcard
  (the server answers NXDOMAIN for it), for sites that keep `www` on the
  public Internet but put `git` on the mesh. **The zone is authoritative
  for everything under the domain**: clients do not check whether a name
  also exists in the public DNS, so a zone must name exactly the names that
  are on the mesh — a wildcard sends *every* name under the domain to the
  node, including those that exist only on the Internet.
- A server that does not answer (as opposed to NXDOMAIN) → the next
  pinned server (§5.3); none left → fall back to the newest zone record
  (§3.3) by any of the pinned servers. Nothing has then proved
  any node reachable, so every target — the server's own node included —
  must answer an echo before its address is handed out (§7).

### 6.1 The server

"The domain's fips DNS server" is a dedicated program (`fips-pubdom-server`,
see [operators.md](operators.md)), **not** fips's own `.fips` responder: that responder binds loopback, answers only `.fips`, and
deliberately drops queries arriving on the mesh interface (it protects the
hosts file from enumeration). The domain server listens on the node's own
fips address, UDP and TCP, default port **5355** (53 needs privileges; the
port travels in the claim and the TXT record anyway), and answers from a small
per-domain zone file. The same program signs and publishes the claim with
the node key, and re-publishes it periodically.

## 7. OS integration

Browsers never ask for TXT and are never changed. The machine's resolver is:

- **Phone (fips2go):** the shim already intercepts all DNS from captured
  apps; the hook is the non-`.fips` branch of `DnsProxy::serve`
  (`shim/src/dns.rs`), which forwards to upstreams today. The step 3 query
  cannot use a kernel socket (the app's UID is outside its own tunnel); it
  goes through the shim's in-process smoltcp stack like the "Mesh names"
  HTTP fetch (`shim/src/meshhttp.rs`), with a UDP socket added. The
  `CNAME npub….fips.` answer is then re-asked to the in-process responder,
  which is what registers the identity with the node.
- **Desktops and servers (Linux, BSD, macOS, Windows):** a standalone
  forwarding resolver daemon (`fips-pubdomd`) in the path for **all names**
  (systemd-resolved `~.`, dnsmasq/unbound upstream, macOS `networksetup`,
  Windows adapter DNS) — it must see every query to do the TXT-first
  discovery of §8. An opt-in restricted mode routes only known domains via
  the OS's per-domain routing (resolved routing domains, dnsmasq
  `server=/domain/`, `/etc/resolver/<domain>`, NRPT) and gives up
  discovery. See [platforms.md](platforms.md).

For a name with a binding and a reachable npub, the resolver:

- answers AAAA with the synthesized `fd…` address,
- answers only the address types (A, AAAA, ANY, CNAME) from the mesh,
  HTTPS/SVCB with NODATA (their hints could steer to the legacy path), and
  passes every other type — MX, TXT, SRV, NS … — to legacy DNS untouched,
  so mail and SPF keep working under a wildcard zone,
- answers A with NODATA and **suppresses the public AAAA** — address sorting
  (RFC 6724, used by bionic, glibc and Chromium) ranks `fd00::/8` below both
  IPv4 and global IPv6, so returning both would almost never use the mesh,
- falls back to the legacy answer on any failure (timeout, parse error, no
  route) and whenever the name is **not over fips**: no binding, binding
  refused (§5.1), or NXDOMAIN from step 3 (§6). A bug must never make a
  public domain unreachable.
- checks reachability before committing: step 3 succeeding proves the
  domain's server `npubxyz` is reachable, which covers `www → self`; when
  the answer names a different node (`npub1234 ≠ npubxyz`), the resolver
  spends up to ~300 ms confirming the local fips node can reach it (route
  or echo) and otherwise falls back to legacy. Once the `fd…` address is
  handed out, DNS is out of the path — a failed connect cannot be
  recovered at this layer, only re-decided at the next lookup (30 s TTL).

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
  publish a claim and forge the matching TXT answer. Multiple independent
  resolvers and pinning reduce this; DNSSEC removes it.
- **Rollback / withholding:** relays can hide a newer event but cannot forge
  one. Keep and persist the highest `created_at` seen per (kind, author, d);
  ignore timestamps more than 10 minutes in the future.
- **Privacy — browsing history:** asking relays about every visited domain
  gives relay operators the browsing history. So the TXT hint is the gate:
  when online, **always** ask the legacy upstream for `_fips-dns.<domain>`
  first (that upstream is about to resolve the name anyway; the negative
  cache keeps it to one query per domain per 6 h) and query relays only for
  domains with a TXT hit. When the machine believes it is online but the
  upstreams do not answer (filtered port 53, stale resolvers), only relays
  on the mesh are asked — a public relay never learns of a domain that DNS
  has not vouched for. Offline (§5.5), the claim is fetched from relays
  directly — those are mesh relays the user chose, or public ones that
  happen to be reachable; the domain is disclosed to them, accepted as the
  price of resolving at all. Step 3 reveals the name only to the domain's
  own server.
- **Limits:** event size, tag counts, label rules and a public-suffix check
  are enforced before anything is cached.

## 9. Phasing

1. **MVP:** claim (§3.1) + TXT verification + pinning + step 3 over UDP with
   CNAME; offline claim fetch via mesh relays (§5.5); unverified refused
   (opt-in marker); phone integration in the fips2go shim; Linux daemon.
2. **DNSSEC proofs** in claims — trustless offline verification of domains
   never seen online; zone records (§3.3) for offline servers.
3. **Attestations** (§3.2) and the trust setting *k*.
4. Desktop resolver daemon on macOS and Windows, then routers
   ([platforms.md](platforms.md)).

## 10. Decisions and open questions

- Kind numbers: proposed in
  [registry-of-kinds #16](https://github.com/nostr-protocol/registry-of-kinds/pull/16);
  the NIP is [nips #2487](https://github.com/nostr-protocol/nips/pull/2487)
  (NIP-DB). Provisional until merged.
- Desktop resolver: standalone daemon in this repo, not inside fips (keeps
  the repo independent of the fips fork; fips's responder has the mesh
  filter, see §6.1).
- Witnesses (phase 2): the user's synced trusted nodes, opt-in.
- Relays: the node's own relay list, fetched by the resolver's own small
  relay client — fips exposes no generic event fetch; sharing its pool is a
  later optimisation.
