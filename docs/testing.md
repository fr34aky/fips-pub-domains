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

## Level 5 — the phone

Not yet run. Build fips2go's `names` branch for arm64, install, Settings →
*Public domain names over fips*, open `http://www.example.org:8321/` in a
captured browser; Diagnostics should show `public name answered over
fips`. Then the FIPS Hotspot or airplane mode with a mesh link for the
pinned offline case. This is where `meshudp.rs` meets a real network.
