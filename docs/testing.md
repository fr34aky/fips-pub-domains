# Testing

Unit tests first, then a ladder of live checks, cheapest first. Each level
catches a different class of problem. The live levels were run
against a real domain (shown here as `example.org`) (a serving node, a
client node, a strfry relay reachable only over the mesh).

## Unit tests

```sh
cargo test --workspace
```

50 tests, no network: the policy tables (precedence, conflicts, pin
changes, offline, anti-rollback), domain and PSL rules, TXT and claim
parsing, DNS synthesis, the TXT combiner, the resolver over fake sources
and a fake mesh, the zone file, the pin file. fips2go's host suite adds the
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

## Level 5 — the phone

Run on a Pixel 9 Pro with fips2go's `names` branch (a debug build from
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
the phone could not discover the domain at all (mesh relays are desktop-only
for now, see [android.md](android.md)); the publisher sent before the relay
handshake had finished ("relay not connected") and now waits; two default
relays were too few once one banned the publisher's address and the other
was unreachable — four now. A CI debug APK is signed with a throwaway key
per run, so device installs are re-signed with one local key to update in
place.
