# Installing

Three binaries come out of this repository, and a machine usually needs
one of them. Each role below has its own section — install, upgrade,
uninstall — complete on its own, so a machine that only resolves follows
"The desktop resolver" and never reads about zone files, and the node
that serves a domain follows "The domain server" and nothing else.

| role | binary | section | then |
|---|---|---|---|
| the node that **serves** a domain | `fips-pubdom-server` | [The domain server](#the-domain-server) | [operators.md](operators.md) |
| a desktop or server that should **resolve** bound names | `fips-pubdomd` (and `fips-pubdom`) | [The desktop resolver](#the-desktop-resolver) | [daemon.md](daemon.md) |
| checks and debugging, no service | `fips-pubdom` | [The CLI only](#the-cli-only) | — |
| a phone | nothing from here | [Android](#android) | [android.md](android.md) |

A machine can hold several roles; the sections combine (the config
directory `/etc/fips-pubdom/` is shared, nothing else overlaps). First,
either way, get the binaries.

## Getting the binaries

Every command in the role sections runs from the directory the binaries
are in: the unpacked release archive, or the repository after a build —
then with `target/release/` in front of each binary name.

### A release archive

[Releases](https://github.com/fr34aky/fips-pub-domains/releases) carry one
archive per platform with all three binaries, the systemd units and the
firewall drop-in (`packaging/`), and a `SHA256SUMS` file:

```sh
V=0.2.4; T=x86_64-unknown-linux-gnu        # or aarch64-unknown-linux-gnu, …-apple-darwin
curl -LO https://github.com/fr34aky/fips-pub-domains/releases/download/v$V/fips-pub-domains-$V-$T.tar.gz
curl -LO https://github.com/fr34aky/fips-pub-domains/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar xzf fips-pub-domains-$V-$T.tar.gz && cd fips-pub-domains-$V-$T
```

### From source

- **Rust 1.88 or newer** (the code uses let-chains). The safe route is
  rustup: `curl https://sh.rustup.rs -sSf | sh`. Distribution packages work
  only where they are current enough — Arch and Fedora usually are; Debian
  13 ships 1.85 and Ubuntu LTS releases older still, so use rustup there.
  `rustc --version` tells you.
- **git**, to clone. No system libraries.

```sh
git clone https://github.com/fr34aky/fips-pub-domains.git
cd fips-pub-domains
cargo build --release
```

That produces `target/release/fips-pubdom-server`, `fips-pubdomd` and
`fips-pubdom`. Build one role only with `cargo build --release -p
pubdom-server` (or `-p pubdom-daemon -p pubdom-cli`). The first build
fetches and compiles the dependencies (a few minutes); later builds are
incremental. `cargo test --workspace` runs the tests, no network needed.

## The domain server

On the fips node that answers for a domain. Nothing here touches the
machine's own DNS.

**Needs:** fips installed and running with a persistent identity — the
server binds the node's fips address and signs with the node key. With
fips's packages the key is `/etc/fips/fips.key`, mode 640, group `fips`;
the unit below runs in that group. Some installs leave the file at mode
600, readable by the `fips` user only: `sudo chmod 640 /etc/fips/fips.key`
restores the packaged layout the unit relies on.

### Install

```sh
sudo install -m755 fips-pubdom-server /usr/bin/           # from source: target/release/fips-pubdom-server
sudo install -m755 fips-pubdom /usr/bin/                  # optional, for checks
sudo install -m644 packaging/systemd/fips-pubdom-server.service /etc/systemd/system/
sudo mkdir -p /etc/fips-pubdom/zones

# firewall: if you run fips's baseline firewall (fips-firewall.service, off
# by default in fips's packages), it drops everything inbound on fips0
# unless a drop-in allows it
sudo cp packaging/common/fips-pubdom.nft /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl try-reload-or-restart fips-firewall
```

Then write the configuration file — the relays to publish to go in it —
the zone file, add the TXT record and start the unit; the whole
procedure is in [operators.md](operators.md):

```sh
sudo tee /etc/fips-pubdom/server.yaml <<'EOF'
zones: /etc/fips-pubdom/zones
publish:
  relays: ["wss://relay.example", "ws://npub1….fips:80"]
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubdom-server
systemctl status fips-pubdom-server
```

The unit runs as an unprivileged throwaway user in group `fips` (to read
the key): **one process serving every** `/etc/fips-pubdom/zones/*.yaml`,
all on the same port — the node's fips address, 5355 by default, UDP and
TCP — and following that directory: a zone file added is served within
a second, one removed is dropped, one edited is re-read. With no zone
file yet the server waits for one. Zones that name a different `port:`
need their own process.

### Upgrade

Get the new binaries ([above](#getting-the-binaries)), then:

```sh
sudo install -m755 fips-pubdom-server /usr/bin/           # and fips-pubdom, if installed
sudo install -m644 packaging/systemd/fips-pubdom-server.service /etc/systemd/system/   # a fixed unit only takes effect once copied
sudo systemctl daemon-reload
sudo systemctl restart fips-pubdom-server
```

Zone files, the configuration and the firewall drop-in survive; the
[CHANGELOG](../CHANGELOG.md) says when a release changes something an
operator must act on. A server installed before 0.2.7 keeps running
from its `server.env` and the zones directory as before; `sudo
fips-pubdom-server init` writes `/etc/fips-pubdom/server.yaml` from
both, and the next restart uses it (new zone files then need no
restart).

### Uninstall

```sh
sudo systemctl disable --now fips-pubdom-server
sudo rm -f /usr/bin/fips-pubdom-server /etc/systemd/system/fips-pubdom-server.service
sudo rm -f /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl daemon-reload
sudo systemctl try-reload-or-restart fips-firewall
sudo rm -rf /etc/fips-pubdom/zones /etc/fips-pubdom/server.yaml /etc/fips-pubdom/server.env   # or all of /etc/fips-pubdom if nothing else uses it
```

The domain's claim stays on the relays until the TXT record is removed
([operators.md](operators.md), "Removing a server").

## The desktop resolver

On a machine running fips whose applications should reach bound names.
`fips-pubdomd` becomes the machine's DNS resolver: bound names resolve
over the mesh, everything else is forwarded to the resolvers the machine
had before.

**Needs:** fips installed and running — the daemon asks fips's `.fips`
responder (`[::1]:5354`) and routes through the node's TUN. Linux with
systemd-resolved, NetworkManager, a standalone dnsmasq or a plain
`resolv.conf`; other platforms are on the [roadmap](roadmap.md) and need
wiring by hand ([platforms.md](platforms.md)).

### Install

```sh
sudo install -m755 fips-pubdomd fips-pubdom /usr/bin/     # from source: target/release/fips-pubdomd target/release/fips-pubdom
sudo install -m644 packaging/systemd/fips-pubdom.service /etc/systemd/system/
sudo fips-pubdomd setup                 # detects resolved / NetworkManager / dnsmasq / plain resolv.conf, writes the config
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubdom
resolvectl query peer.fips              # .fips still works
sudo fips-pubdom verify example.org     # a bound domain verifies
```

`setup` names the backend it chose (or takes `--backend`); with
NetworkManager or a plain `resolv.conf` the daemon listens on port 53. It
says when the listen addresses changed — restart the daemon then, and
after `teardown`, which restores the config. Everything `setup` changes is
undone by `sudo fips-pubdomd teardown`. Configuration, behaviour and
troubleshooting: [daemon.md](daemon.md).

On a daemon host the CLI shares the daemon's config and therefore its pin
file under `/var/lib/fips-pubdom/`, which is root-owned: run it with
`sudo`, or give yourself a user-level config as in
[The CLI only](#the-cli-only).

### Upgrade

Get the new binaries ([above](#getting-the-binaries)), then:

```sh
sudo install -m755 fips-pubdomd fips-pubdom /usr/bin/
sudo install -m644 packaging/systemd/fips-pubdom.service /etc/systemd/system/   # a fixed unit only takes effect once copied
sudo systemctl daemon-reload
sudo systemctl restart fips-pubdom
```

`setup` is not run again: the OS wiring, `/etc/fips-pubdom/config.yaml`
and the pins (`/var/lib/fips-pubdom/pins.json`) survive an upgrade. The
[CHANGELOG](../CHANGELOG.md) says when a release adds a config key worth
setting; new keys have defaults, an old config keeps working.

### Uninstall

```sh
sudo systemctl disable --now fips-pubdom
sudo fips-pubdomd teardown                                # restores the OS resolver configuration
sudo rm -f /usr/bin/fips-pubdomd /usr/bin/fips-pubdom /etc/systemd/system/fips-pubdom.service
sudo systemctl daemon-reload
sudo rm -rf /etc/fips-pubdom /var/lib/fips-pubdom        # config and pins — not if the domain server shares the machine
```

### Trying it without touching the OS resolver

For a look, or for tests, the daemon runs from any directory with a
config that names a writable pin path and explicit upstreams (without
upstreams it considers itself offline and answers SERVFAIL for every
legacy name), and is queried directly:

```sh
printf 'pins: ./pins.json\nupstreams: ["9.9.9.9", "1.1.1.1"]\n' > ./config.yaml
./fips-pubdomd --config ./config.yaml run     # listens on [::1]:5356 / 127.0.0.1:5356
dig @::1 -p 5356 www.example.org AAAA
dig @::1 -p 5356 peer.fips AAAA
```

## The CLI only

`fips-pubdom` needs no service and no root: `lookup` runs the full
resolver path — including the mesh query through the local fips node —
and prints the answer an application would get; `verify` prints every
input to the decision without applying it; `claims`, `pins`, `attest`
and `attestations` are the rest. It reads the daemon's config
(`/etc/fips-pubdom/config.yaml`) where there is one, or `--config`; a
config with just a `pins:` path in a writable place is enough.

### Install

```sh
install -m755 fips-pubdom ~/.local/bin/                   # from source: target/release/fips-pubdom
printf 'pins: %s/.local/share/fips-pubdom/pins.json\n' "$HOME" > ~/.config/fips-pubdom.yaml
fips-pubdom --config ~/.config/fips-pubdom.yaml verify example.org
fips-pubdom --config ~/.config/fips-pubdom.yaml lookup www.example.org
fips-pubdom --config ~/.config/fips-pubdom.yaml --offline lookup www.example.org
```

### Upgrade

Get the new binary ([above](#getting-the-binaries)) and copy it over:
`install -m755 fips-pubdom ~/.local/bin/`. The config and the pin file
stay.

### Uninstall

```sh
rm -f ~/.local/bin/fips-pubdom ~/.config/fips-pubdom.yaml
rm -rf ~/.local/share/fips-pubdom
```

## Android

There is nothing to install from this repository: fips2go embeds the
library crates. Install fips2go from its
[releases](https://github.com/fr34aky/fips2go/releases) or from Zapstore,
or build it as its README's "Build" section describes — the native shim
with `./build-native.sh arm64-v8a` (needs the Android NDK), then the APK
from the `android/` directory with Gradle and JDK 17. The feature is on by
default under Settings → *Public domain names over fips*; relays on the
mesh go in *Mesh relays for public names* below it. Details and limits:
[android.md](android.md).

## Other platforms

The library crates build everywhere Rust does, including
`aarch64-linux-android` (CI checks), and the release archives include
macOS and Windows builds of the binaries. `setup` has no backend there
yet, so the daemon must be wired in by hand (`/etc/resolver/`,
`networksetup`, NRPT) — see [platforms.md](platforms.md) for the plan.
