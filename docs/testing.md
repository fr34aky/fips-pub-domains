# Testing

Unit tests first, then a ladder of live checks, cheapest first. Each level
catches a different class of problem. The live levels were run
against a real domain (shown here as `example.org`) (a serving node, a
client node, a strfry relay reachable only over the mesh).

## Unit tests

```sh
cargo test --workspace
```

No network: the policy tables (precedence, conflicts, pin
changes, offline, anti-rollback), domain and PSL rules, TXT and claim
parsing, DNS synthesis, the TXT combiner, the resolver over fake sources
and a fake mesh, the zone file, the pin file, and DNSSEC proofs over a
synthetic signed hierarchy (root → org → example.org with a split KSK/ZSK,
a test trust anchor): valid, expired, not yet valid, unanchored root,
missing DS, forged TXT, a DS signed by the child, garbage.
`PUBDOM_LIVE_DOMAIN=example.org cargo test -p pubdom-resolve live --
--ignored` builds and verifies the chain of a real signed domain. fips2go's host suite adds the
smoltcp UDP exchange against a userspace server and the proxy with a fake
resolver.

## Level 1 — the server, from a real peer

On the serving node: firewall drop-in, then `fips-pubdom-server serve`. From
any linked node:

```
$ dig @fdd9:…:8f4d -p 5355 www.example.org AAAA +short
npub1uyutnt7z78e7rpjx4dtkms2ukfs6kkq0feeqa5jqllnylmrpjkqs35ysdl.fips.
$ dig @fdd9:…:8f4d -p 5355 mail.example.org AAAA | grep -E "status|flags"
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 63396
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
$ dig @fdd9:…:8f4d -p 5355 www.example.org +tcp +short
npub1uyutnt7z78e7rpjx4dtkms2ukfs6kkq0feeqa5jqllnylmrpjkqs35ysdl.fips.
```

Proves: the firewall rule, UDP and TCP over the mesh, the wildcard, the
`legacy` carve-out, and the zone hot reload (the `mail: legacy` line was
added while serving).

## Level 2 — the claim on a relay

```
$ fips-pubdom-server --key /etc/fips/fips.key publish --zone example.org.yaml --relay ws://npub1c8n8….fips:80
INFO claim published domain=example.org relays=["ws://npub1c8n8….fips"]
```

Then, with that relay in `mesh_relays`:

```
$ fips-pubdom verify example.org
txt: Hit { records: [TxtRecord { npub: npub1uyut…, port: Some(5355) }], method: Dnssec } (ttl Some(300))
claim events: 1
  claim by npub1uyut… port 5355 created_at 1790591325
decision: Bound(Binding { domain: "example.org", npub: npub1uyut…, port: 5355, method: Dnssec, … })

$ fips-pubdom --offline claims example.org          # the claim, fetched through the mesh relay
$ fips-pubdom lookup www.example.org                # over fips: CNAME + AAAA fdd9:…; pinned
$ fips-pubdom --offline lookup www.example.org      # from the pin
$ fips-pubdom --offline lookup www.example.org      # (fresh pin file) not over fips: Unverified
$ … with allow_unverified_offline: true            # over fips, with "resolving through an UNVERIFIED binding (opt-in)"
$ fips-pubdom lookup mail.example.org               # not over fips (legacy passthrough)
$ fips-pubdom lookup www.github.com                # not over fips (legacy passthrough)
```

Things this level found: the relay rejected writes until the node's hex
pubkey was on its write-policy allowlist; nostr-sdk cannot dial `[fd…]`
literals (hence `.fips` hostnames); online fetches had to include the mesh
relays.

## Level 3 — the daemon on a second node

On the client node (systemd-resolved): install, `sudo fips-pubdomd
setup`, `systemctl enable --now fips-pubdom`.

```
$ resolvectl query www.example.org
www.example.org: fdd9:e5a:a4d9:2fb4:4bf8:b66b:4b1d:8f4d -- link: lo
                (npub1uyutnt7z78e7rpjx4dtkms2ukfs6kkq0feeqa5jqllnylmrpjkqs35ysdl.fips)
-- Information acquired via protocol DNS in 2.1312s.
$ curl -s http://www.example.org:8321/ | head -c 80        # fips-ui on the serving node, by name, over the mesh
<!doctype html>
<html lang="en">
$ fips-pubdom pins list
example.org    npub1uyut…:5355    Dnssec    verified_at 1790592675
$ resolvectl query peer.fips                          # .fips still works
$ curl -sI https://github.com | head -1                    # HTTP/2 200
```

Things this level found: resolved merges global drop-ins into one pool (the
daemon now forwards `.fips` itself and its drop-in resets the lists), and
the LAN's DHCP search domain `example.org` shadowed the daemon for the very
domain under test until removed from the link ([daemon.md](daemon.md)).

## Level 4 — offline

On the client node, with legacy DNS blocked but the mesh intact
(`iptables -I OUTPUT ! -o lo -p udp --dport 53 -j DROP` and `ip6tables`):

```
$ sudo resolvectl flush-caches
$ resolvectl query www.example.org
www.example.org: fdd9:e5a:a4d9:2fb4:4bf8:b66b:4b1d:8f4d -- link: lo
-- Information acquired via protocol DNS in 5.5ms.
$ resolvectl query github.com
github.com: resolve call failed: … SERVFAIL
```

Then `sudo fips-pubdomd teardown`: `resolvectl query www.example.org` shows
the public address again, `-- link: eth0`. Nothing left behind.

(Blocking port 53 *including* loopback also blocks resolved's stub at
`127.0.0.53`; `resolvectl query` still works because it uses D-Bus, but
`curl` and `getent` do not. Exclude `lo`.)

## Level 4d — a domain never seen, offline, from the DNSSEC proof

The serving node publishes its claim with a proof (`serve --publish`; the
log shows `claim published … dnssec_proof_until=Some(…)`, 3.8 KB of chain
for a DNSSEC-signed `.ch`-style domain with ECDSA keys under an RSA root).
On a client with an **empty pin file**, no public relay and no legacy DNS —
only the mesh relay:

```
$ fips-pubdom --config ./config-proof.yaml --offline verify example.org
pins: none
txt: Unreachable (ttl None)
claim events: 1
  claim by npub1… port 5355 created_at …: DNSSEC proof valid until 1791417600
decision: Bound([Binding { domain: "example.org", npub: npub1…, port: 5355, method: Dnssec, … }])
```

Before proofs, the same situation was `NotOverFips(Unverified)`. The strfry
relay accepted the 5 KB event without configuration changes.

## Level 3b — a third node, from the install guide

A fresh Arch/Omarchy desktop following [install.md](install.md) verbatim:
built with the distribution's Rust, `setup`, the unit. Its first query
discovered and pinned the domain on its own (`binding verified and pinned
… method=Dnssec`, 2.1 s), `www` resolved to the mesh, a subdomain that lives
only on the Internet resolved to its public address, `.fips` names kept
working through the daemon. Found: the demo zone's `*` wildcard had claimed
that Internet-only subdomain — the operators guide now says when a wildcard
is appropriate — and the search-domain warning listed fips's own `fips`
routing domain, which it no longer does.

## The packaged server unit

The unit is part of the install path and has to be started, not just
read: `systemd-analyze verify` accepts a unit whose `ExecStart` systemd
itself rewrites (0.2.0 shipped one that passed `--zone /bin/sh`). With a
zone in `/etc/fips-pubdom/zones/` and `server.env` set, `systemctl start
fips-pubdom-server` must log `serving` and `claim published`; with the
directory empty it must stop once with "no zone files". `cargo test`
guards the escaping: every `%` and `$` in the shipped units' `ExecStart`
lines must be doubled.

## Level 3c — a name pointing at a node that does not exist

Zone entry `ghost: <npub of nobody>`. The server answers the CNAME (the
zone says so); the client registers the identity, sends an ICMPv6 echo,
gets nothing within 1.5 s and hands the application the legacy answer:

```
$ fips-pubdom lookup ghost.example.org      # 1.9 s
ghost.example.org: not over fips (legacy passthrough)
$ fips-pubdom lookup pixel.example.org      # a phone on the mesh: echo ~250 ms, then answered
pixel.example.org: over fips, rcode NoError
```

Found here: the reachability check had been the responder registration,
which succeeds for any well-formed npub — the ghost resolved to a mesh
address nobody answers at. The check is an echo now. On the phone the same
zone entry logs `target node not reachable through the local fips node;
using the legacy answer` (the echo runs through the smoltcp stack), while
names pointing at the phone itself and at another desktop node resolve
over the mesh. A negative verdict is remembered for 30 s so a browser's
A/AAAA/HTTPS trio waits out one echo budget, not three.

## Level 4b — the domain's server is down

The server publishes its zone record with the claim (`publish` sends
both; `serve --publish` re-sends on start, every 24 h, and on a zone
change). With the server process stopped and the resolver's step 3 getting
no answer:

```
$ fips-pubdom lookup home.example.org     # 485 ms
domain server unreachable; answering from its zone record name=home.example.org npub=npub1…
home.example.org: over fips, rcode NoError
$ fips-pubdom lookup www.example.org      # the server's own node, still up: echo answers
www.example.org: over fips, rcode NoError
$ fips-pubdom lookup mail.example.org     # `legacy` in the zone
mail.example.org: not over fips (legacy passthrough)
$ fips-pubdom zone example.org
example.org: zone record by npub1… created_at …
  home         Node(…)   mail  Legacy   pixel  Node(…)   www  Author
```

Every target answered from the record has to pass the echo, the server's
own node included — nothing else has proved any of them reachable.

## Level 4c — redundant servers

Unit-tested (`redundant_servers_fail_over_and_retry_after_the_backoff`,
`a_failed_server_is_retried_once_its_backoff_expires`): two TXT-named
servers both claiming → both pinned; the primary's DNS silent → the second
answers after the primary's UDP attempt and retry; the next name goes to
the second server directly while the primary is in its backoff window; with
the window expired the primary is asked again. An existing single-entry
pin file loads and resolves unchanged.

Live, with a second node serving the same zone file and a second TXT
record: a fresh client pinned both servers; with the primary's process
stopped, the query logged `domain server did not answer; trying the next`
and was answered by the second server (not the zone record); with the
primary back, lookups returned to it. Two things this level found: a
client configured with only a mesh relay never sees the second server's
claim unless that relay accepts the second key too (its allow-list), so
it pins one server and reaches the other only through the zone record;
and the failover log said "trying the next" with nothing left to try —
it now says which.

## Level 4e — attestations

Phase 3, run live on 2026-10-01 on the reference node alone, which can
be both the witness and the client: a witness keeps no pins of its own
and a client's trust list is just configuration.

**Witness.** `fips-pubdom attest example.org --key /etc/fips/fips.key`
verified the record (DNSSEC on the first run, two agreeing resolvers on
the second, which used a config with `dnssec: false`), fetched the claims
from every relay, and published one attestation naming the one server:

```
example.org: attested 1 server(s) by Dns, accepted by ws://npub1….fips, wss://relay.damus.io, wss://relay.primal.net, wss://nos.lol
  npub1…server
```

Found on the way: the first run used the daemon's config, which lists no
mesh relay, so the attestation reached the public relays only — and a
client reads attestations from mesh relays alone (spec §3.2). The
operators guide says to configure one; this is what it looks like when
you do not: `attestations by trusted witnesses: 0 (of 1 configured)`.

**Client.** A throwaway config: `dnssec: false` (so the claim's DNSSEC
proof cannot be used and attestations are the only path), the node's own
npub as the sole witness, `attestation_threshold: 1`, an empty pin file,
the mesh relay. Offline:

```
$ fips-pubdom --config client.yaml --offline verify example.org
pins: none
txt: Unreachable (ttl None)
claim events: 2
attestations by trusted witnesses: 1 (of 1 configured, k = 1)
  npub1…witness attests [Npub(npub1…server)] Dns verified_at 1790854805
  claim by npub1…server port 5355 created_at 1790812492: DNSSEC proof signed at …, valid until …
  claim by npub1…old port 5355 created_at 1790638494: no DNSSEC proof
decision: Bound([Binding { domain: "example.org", npub: Npub(npub1…server), port: 5355, method: Attested, … }])
pin changes: [Put(…)] (not applied by `verify`)

$ fips-pubdom --config client.yaml --offline lookup relay.example.org
relay.example.org: over fips, rcode NoError
  relay.example.org 30 CNAME npub1….fips
  npub1….fips 30 AAAA fd6b:…
```

The lookup pinned the domain as `attested` (the pin file shows it) and
step 3 to the server over the mesh answered the name. The second claim,
by a key the record no longer names and without a proof, played no part:
attestations vouch only for the server they name, and the witness named
one. (`www.example.org` is no longer in the server's zone, hence the
lookup of `relay`.)

## Level 6 — the NetworkManager backend (Ubuntu 22.04, the home node)

Run on 2026-10-01 on a node that normally runs systemd-resolved. Steps:
`fips-pubdomd teardown` (which found the resolved drop-in of an older
install with no record and removed it), `systemctl disable --now
systemd-resolved`, the stub symlink removed, NetworkManager restarted.

Found on the way: with resolved stopped, NM still chose its resolved
mode — `/run/NetworkManager/resolv.conf` named `127.0.0.53` — because
`/run/systemd/resolve` outlives a stopped resolved and NM goes by it, and
it created no `/etc/resolv.conf` at all. `setup` handled both: it
detected NetworkManager (resolved inactive, by `systemctl is-active`),
recorded an absent resolv.conf, wrote `dns=none`, and after the reload
NM's file listed the DHCP servers:

```
backend: NetworkManager
upstreams now: [192.168.128.254, fd01::1]
$ cat /run/NetworkManager/resolv.conf
search example.org
nameserver 192.168.128.254
nameserver fd01::1
```

The daemon on port 53 answered a legacy name through those servers and
`relay.example.org` over fips, with no resolved-only search-domain
warning in its log. An NM restart and a connection renewal (`nmcli con
up`) both left our resolv.conf alone and kept NM's file current — the
assumption the backend rests on. `teardown` removed the drop-in and our
resolv.conf (nothing to restore: none had existed), and the node went
back to resolved with the stub symlink recreated by hand.

Found afterwards: the config kept `listen` on port 53 after the
NetworkManager teardown, which the following resolved `setup` carried
into its drop-in — working but surprising; `setup` now backs the config
up and `teardown` restores it. And back on resolved, the LAN
search domain shadowed the bound domain again (the `resolvectl domain`
fix of level 3 is transient, lost with the NM restarts): the daemon's
start-up warning names it.

**Not yet run live:** the standalone dnsmasq and plain-`resolv.conf`
backends (tests in a temporary root only), and the upstreams-file
watcher (unit-tested against a temporary directory; the live check is a
`resolvectl dns <link> …` change reaching the daemon's "upstreams
changed" line within a second, under the unit's `ProtectSystem=strict`).

## Level 5 — the phone

Run on a Pixel 9 Pro with fips2go (then its `names` branch; a debug build from
CI, re-signed with one local key so later builds install in place), the
browser captured as a mesh app, and the demo domain pinned:

```
I fips_android::engine: public domain names over fips on pins="/data/user/0/org.fips.android/files/names-pins.json"
I fips_android::dns: public name answered over fips qname=www.example.org qtype=1
I fips_android::dns: public name answered over fips qname=www.example.org qtype=28
```

The browser then reached fips-ui on the serving node **over the mesh, by
public name** — the page shell rendered before fips-ui's own Host-header
guard refused `www.example.org:8321` (an application-level allow-list of
its own; the request had already crossed the mesh). That exercises the
phone-specific code end to end: the resolver in the proxy, step 3 through
the smoltcp UDP socket (`meshudp.rs`), the responder registration, the
synthesized AAAA with the public addresses suppressed.

Found on this level and fixed: with the claim only on a relay inside the
mesh (unreachable from the phone) the resolver refused despite the pin and
a TXT record naming the pinned server — a policy gap, since a pin is a
verified binding (spec §5.1 step 2). Reproduced on the desktop first, fixed
in `pubdom-core` with a test, then re-tested on the device.

**First-visit discovery** on the phone, once the claim was on a public relay
the phone's relay list included (with no pin file present):

```
I pubdom_resolve::resolver: binding verified and pinned domain="example.org" npub=npub1uyut… method=Dnssec
I fips_android::dns: public name answered over fips qname=www.example.org qtype=28
```

The TXT record was DNSSEC-validated by hickory on the device through the
phone's own upstreams, the claim fetched from the relay, the pin written
by the app.

**Offline** on the phone: app restarted (caches empty), the phone's
Internet blocked at the router (LAN intact, so the direct mesh link to the
serving node survived). The name answered from the pin with every relay
logging `Connection refused` and the TXT upstreams unreachable; the browser
reached the serving node over the mesh; `https://github.com/` did not load.

Things this level found: with the claim only on a relay inside the mesh
the phone could not discover the domain at all (mesh relays were
desktop-only then; since fips2go #59 the phone reaches them, see
[android.md](android.md)); the publisher sent before the relay
handshake had finished ("relay not connected") and now waits; two default
relays were too few once one banned the publisher's address and the other
was unreachable — four now. A CI debug APK is signed with a throwaway key
per run, so device installs are re-signed with one local key to update in
place.

**A name bound to a third node** (`relay.example.org`, the zone pointing
it at the mesh relay's own node rather than the server): the phone showed
the hoster's parking page every time, while the daemon resolved it. The
shim's log showed the lookup *succeeding* — both `public name answered
over fips` lines — about 2.8 s after the query, against the 3.5 s budget:
2 s of it was the claim fetch waiting out its timeout for a relay in the
pool that never sent EOSE. One cold lookup had overrun, the proxy forwarded
the legacy answer, and the hoster's wildcard made that a real address with
a 300 s TTL that Android's resolver kept; the finished lookup's cached
decision was never asked for. Fixed in two places (fips-pub-domains #11,
fips2go #60): the claim fetch returns 750 ms after the first relay that
delivered a claim, and a legacy answer forwarded during an overrun has its
TTLs capped at 5 s. Re-tested on the device from a fresh start (caches
empty), the first lookup:

```
12:27:04.70  intent: open http://relay.example.org/?v=…
12:27:06.71  Session established (initiator, XK) src=npub1…   # step 3 to the server
12:27:06.80  public name answered over fips qname=relay.example.org qtype=28
12:27:06.80  public name answered over fips qname=relay.example.org qtype=1
12:27:07.82  Timeout reached for subscription, auto-closing   # the quiet relay, after the answer
```

About 2 s from the intent, so under 1.8 s for the lookup itself, and the
browser showed the relay's own page over the mesh at the first attempt.
Note for anyone reading the device: the browser's own host cache
(Chromium, 60 s) can show the legacy page once more after an overrun; the
proxy's log, not the page, says what was answered.

The same name in **Amethyst** (`ws://relay.example.org`): the proxy
answered over fips, but Amethyst routed the relay through its built-in
Tor (its rule knows only literal local and overlay addresses), so the
connection went to the legacy address and the relay showed 0 B. The
`ws://<npub>.fips` entry for the same node carried traffic. An app-side
limit, noted in [android.md](android.md).

## Level 5c — the phone, offline, verified by a witness

2026-10-01, Pixel 9 Pro on the release-signed build with the DNSSEC
switch (fips2go #65). Settings: witness = the reference node, k = 1,
DNSSEC off, the mesh relay; **Forget verified domains**; the Internet
blocked at the router and, since the router still answered DNS itself,
the Wi-Fi's DNS set static to `192.0.2.1`; mobile data off (Android had
quietly fallen back to it the first time, and the test ran online); app
reconnected, after which the node hung under the reference node over the
LAN (`new_parent=…`) and the relay session came up through it. The first
lookup overran its budget as every offline first lookup does, the
decision landed right after, and the retry answered:

```
public name still deciding; legacy answer for a few seconds qname=relay.example.org qtype=28
binding verified and pinned domain="example.org" npub=npub1…server method=Attested
public name answered over fips qname=relay.example.org qtype=1
```

The browser showed the relay's own page over the mesh. Found on the way:
with DNSSEC off and the Internet reachable, the same sequence pinned the
domain with method `Dns` — the switch doing its job, and a reminder that
"offline" means the TXT upstreams unreachable, not merely a browser that
cannot load pages. The node's relay connection failed through a dead
Internet parent until the app was reconnected; the reconnect is what
made the node pick the LAN peer.

**With the Internet flag** (fips2go #67, later the same day): the Wi-Fi
re-joined with its DNS pointing at an unreachable address, so Android's
own probe failed — `public names: internet not validated` within 3 s,
the shim's TXT wait down to 500 ms, the node running on. Pins forgotten,
app reconnected, and the first lookup of `relay.example.org` logged no
"still deciding": `binding verified and pinned … method=Dnssec` (the
claim's proof, through the mesh relay) 2.5 s after the browser intent,
then `answered over fips` for A and AAAA — inside the budget, where the
morning's offline first lookups had all resolved on the retry only.
Android does not re-probe a validated Wi-Fi on its own when the Internet
behind it disappears: a router block left the flag at "validated" for
three minutes until the Wi-Fi was re-joined, which is when a fresh probe
runs.

## Level 5b — the phone, offline, a domain never seen

fips2go with a mesh relay configured (`ws://npub1….fips:80`), its pin file
emptied, the phone's Internet blocked at the router, and the phone linked
over LAN to a node that reaches the relay. Opening `www.example.org`: the
first lookup overran the 3.5 s budget (TXT timeout, then the relay) and the
browser got the legacy answer, but the lookup finished in the background —
`binding verified and pinned … method=Dnssec` from the claim's proof — and
the retry was answered over fips (A and AAAA). Only the server whose claim
carried a proof was pinned. Found on the way: a lookup cancelled at the
budget never cached anything, so the domain never resolved offline; the
shim now lets it finish. The phone needs a mesh path to the relay: on a
different LAN than the node that reaches it, discovery failed until both
joined the same one.
