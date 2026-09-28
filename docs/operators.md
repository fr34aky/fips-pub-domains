# Serving a domain over fips

What the operator of `example.org` does so that fips users reach
`www.example.org` over the mesh. Four steps: a zone file, a DNS record, a
firewall rule, and the running server (which publishes the claim).

## Prerequisites

- `fips-pubdom-server` built and installed ([install.md](install.md)).
- A fips node with a persistent identity (`/etc/fips/fips.key`; the user
  running the server must be able to read it — it is group `fips`).
- Control of the domain's DNS. DNSSEC on the zone is optional but makes the
  binding cryptographically verifiable and, later, verifiable offline.
- A Nostr relay to publish to. Any public relay works; a relay reachable
  over the mesh additionally lets clients discover the domain with no
  Internet at all ([daemon.md](daemon.md), "mesh relays").

## 1. The zone file

`/etc/fips-pubdom/zones/example.org.yaml`:

```yaml
domain: example.org
port: 5355            # optional; must match the TXT record and the claim
names:
  www: self           # served by this node
  git: npub1…         # served by another node
  mail: legacy        # explicitly NOT over fips, even under the wildcard
  "*": self           # everything else
```

Rules: labels follow hostname syntax (≤ 63 characters, letters, digits,
hyphens), `@` is the apex, `*` the wildcard, and a label may not look like
an npub. `legacy` is how a site keeps `www` on the public Internet while
putting `git` on the mesh: the server answers NXDOMAIN, and the client
turns that into an ordinary legacy lookup. The file is re-read whenever its
mtime changes; a broken edit keeps the last good zone.

## 2. The DNS record

```sh
fips-pubdom-server --key /etc/fips/fips.key txt --zone /etc/fips-pubdom/zones/example.org.yaml
```
prints the record to add at your DNS hoster:

```
_fips-dns.example.org.  3600  IN  TXT  "v=fips1 npub=npub1uyutnt7z78e7rpjx4dtkms2ukfs6kkq0feeqa5jqllnylmrpjkqs35ysdl port=5355"
```

Enter the npub **without** `.fips` — it is data, not a hostname. Several
records may name several servers. Check propagation with
`dig _fips-dns.example.org TXT +short`; with a signed zone,
`dig … +dnssec` answers with the `ad` flag from a validating resolver.

This record is what turns a claim into a verified binding. Without it,
clients refuse the claim.

## 3. The firewall

The fips baseline firewall drops everything inbound on `fips0` that a
drop-in does not allow:

```sh
sudo cp packaging/common/fips-pubdom.nft /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl reload fips-firewall
sudo nft list chain inet fips inbound | grep 5355     # two rules: udp and tcp
```

## 4. The server and the claim

```sh
fips-pubdom-server --key /etc/fips/fips.key serve \
    --zone /etc/fips-pubdom/zones/example.org.yaml \
    --publish --relay wss://relay.example --relay ws://npub1….fips:80
```

`serve` listens on the node's own fips address, UDP and TCP, port 5355.
`--publish` signs the claim (kind 37197: `d=example.org`,
`service fips-dns 5355`) with the node key and sends it to every `--relay`
at start and every 24 h; it is an addressable event, so a re-publish
replaces the previous one. `publish --dry-run` prints the signed event
instead, for other tooling. A relay may gate writes on a pubkey allowlist —
strfry's write-policy plugin, for instance — in which case the node's hex
pubkey must be on it.

`packaging/systemd/fips-pubdom-server.service` runs `serve` for every zone
in `/etc/fips-pubdom/zones/` as group `fips`.

## Checking from another node

From any linked fips node, with the server's fips address:

```sh
dig @fdd9:…:8f4d -p 5355 www.example.org AAAA +short     # → npub1uyut….fips.
dig @fdd9:…:8f4d -p 5355 mail.example.org AAAA            # → status: NXDOMAIN, flags qr aa
dig @fdd9:…:8f4d -p 5355 www.example.org +tcp +short     # the truncation path
```

And with a resolver installed ([daemon.md](daemon.md)):
`fips-pubdom verify example.org` should end in `decision: Bound(… method:
Dnssec …)` (or `Dns` for an unsigned zone).

## What the server does not do

- It does not prove you own the domain — the TXT record does. A claim
  without one is refused by every client.
- It does not serve anything but the CNAME to a node. HTTP, TLS
  certificates, and what the node answers on its ports are the node's
  business; a site using the same name on both networks should serve its
  certificate on its fips address too (HSTS and secure-context APIs still
  require `https://`).
- It does not need the Internet. Once the claim is on a relay clients can
  reach, and the record is in DNS, the server itself only ever talks over
  the mesh.
