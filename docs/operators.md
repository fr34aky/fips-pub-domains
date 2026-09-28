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
an npub. **Use the wildcard only if everything under the domain really is
on the mesh**: it makes the server claim every name, including
`cloud.example.org` that lives only on the public Internet, and clients
will then send that name to your node and fail. A site with a few mesh
services lists them and leaves the wildcard out; a site that wants the
wildcard carves the Internet-only names out with `legacy`. `legacy` is how a site keeps `www` on the public Internet while
putting `git` on the mesh: the server answers NXDOMAIN, and the client
turns that into an ordinary legacy lookup. (A new file under the unit needs a restart.) The file is re-read whenever its
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
sudo systemctl try-reload-or-restart fips-firewall    # no-op if you do not run fips's firewall
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
`service fips-dns 5355`) **and the zone record** (kind 37199: the `names`
of the zone file) with the node key and sends them to every `--relay` — at
start, every 24 h, and whenever a zone file changes. Both are addressable
events, so a re-publish replaces the previous one. The zone record is what
lets a client resolve `git.example.org` to the node serving it while this
server is unreachable; without it a name resolves only while the server
answers. `publish --dry-run` prints both signed events instead, for other
tooling. A relay may gate writes on a pubkey allowlist —
strfry's write-policy plugin, for instance — in which case the node's hex
pubkey must be on it.

**DNSSEC proof.** If the domain's zone is DNSSEC-signed, the claim also
carries a proof (`dnssec` tag): the signed TXT record and the chain of
keys up to the DNS root. A client that has never seen the domain and has
no Internet — only the mesh and a relay on it — verifies the claim with
that proof alone. The server collects the chain from the system's
resolvers, then 9.9.9.9 and 1.1.1.1 (`--dns <ip>` to choose; a local stub
that strips DNSSEC records does not work), checks it as a client would, and
re-publishes before its signatures expire: halfway through their remaining
validity, every 24 h at the latest. The log line `claim published …
dnssec_proof_until=…` shows it; for an unsigned zone the claim goes out
without a proof and a warning says so. `--no-dnssec-proof` turns it off.

If collecting fails (a resolver timing out), the last chain is kept while
it has more than an hour left and the server tries again in an hour —
after a restart too, taken from its own newest claim on the relays. Once
the record no longer names this server's key (a key rotation, or a record
set up for another node), the claim goes out without a proof, hourly, with
a warning — an older proof would be evidence for a retired key. Each zone
is scheduled on its own. `publish --dry-run` collects the chain but never
contacts a relay, so while DNS fails it shows the claim without the proof
a real run would restore.

`packaging/systemd/fips-pubdom-server.service` runs one `serve` for all the
zones in `/etc/fips-pubdom/zones/` (same port for all) as group `fips`;
`--publish --relay …` go into `/etc/fips-pubdom/server.env` as
`PUBDOM_SERVER_ARGS=…` ([install.md](install.md)).

## Redundant servers

Run the server on two (or more) nodes with the **same zone file**, each
with its own key, and add one TXT record per node:

```
_fips-dns.example.org.  TXT  "v=fips1 npub=<node A> port=5355"
_fips-dns.example.org.  TXT  "v=fips1 npub=<node B> port=5355"
```

Each node publishes its own claim and zone record (`serve --publish`).
Clients pin every server the record names, ask them in order, fail over
when one does not answer, and retry a failed server after a growing
backoff (5 min → 15 → 45 → 3 h). Names that point at `self` differ per
server — `www: self` on node A resolves to node A when A answers and to
node B when only B does — so either keep such names identical in meaning
(the same site on both nodes) or name the node explicitly.

## Checking from another node

From any linked fips node, with the server's fips address:

```sh
dig @fdd9:…:8f4d -p 5355 www.example.org AAAA +short     # → npub1uyut….fips.
dig @fdd9:…:8f4d -p 5355 mail.example.org AAAA            # → status: NXDOMAIN, flags qr aa
dig @fdd9:…:8f4d -p 5355 www.example.org +tcp +short     # the truncation path
```

And with a resolver installed ([daemon.md](daemon.md)):
`fips-pubdom verify example.org` should end in `decision: Bound(… method:
Dnssec …)` (or `Dns` for an unsigned zone), and list the claim with
`DNSSEC proof valid until <unix time>`. `fips-pubdom --offline verify
example.org` with an empty pin file shows what a client that never saw the
domain decides from the proof alone.

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
