# Building and installing

Every component builds from this one repository with a stable Rust
toolchain; nothing needs system libraries. Which binaries you install
depends on the role of the machine:

| role | install | guide |
|---|---|---|
| a node that **serves** a domain | `fips-pubdom-server` (+ its unit, the firewall drop-in) | [operators.md](operators.md) |
| a desktop/server that should **resolve** bound names | `fips-pubdomd` (+ its unit), `fips-pubdom` | [daemon.md](daemon.md) |
| a phone | nothing from here: built into fips2go | [android.md](android.md) |
| debugging either | `fips-pubdom` | below |

## Prerequisites

- **Rust 1.88 or newer** (the code uses let-chains). The safe route is
  rustup: `curl https://sh.rustup.rs -sSf | sh`. Distribution packages work
  only where they are current enough — Arch and Fedora usually are; Debian
  13 ships 1.85 and Ubuntu LTS releases older still, so use rustup there.
  `rustc --version` tells you.
- **git**, to clone.
- **fips** installed and running on the machine — both roles talk to the
  local node: the server binds the node's fips address, the daemon asks
  fips's `.fips` responder (`[::1]:5354`) and routes through the node's TUN.
- For the server: read access to the node key. With fips's packages the key
  is `/etc/fips/fips.key`, mode 640, group `fips` — add the serving user to
  that group (`sudo usermod -aG fips $USER`, re-login) or run the unit,
  which does it for you. Some installs leave the file at mode 600, readable
  by the `fips` user only: `sudo chmod 640 /etc/fips/fips.key` restores the
  packaged layout the unit relies on.

The repository is private at the moment: cloning needs a GitHub account
with access (`gh auth login`, or an SSH key).

## Build

```sh
git clone https://github.com/fr34aky/fips-pub-domains.git
cd fips-pub-domains
cargo build --release
```

That produces, in `target/release/`:

| binary | crate |
|---|---|
| `fips-pubdom-server` | `pubdom-server` |
| `fips-pubdomd` | `pubdom-daemon` |
| `fips-pubdom` | `pubdom-cli` |

Build only what you need with `cargo build --release -p pubdom-server`
(or `-p pubdom-daemon -p pubdom-cli`). The first build fetches and compiles
the dependencies (a few minutes); later builds are incremental.

Run the tests with `cargo test --workspace` — no network needed.

## Install: the domain server

On the node that serves the domain:

```sh
sudo install -m755 target/release/fips-pubdom-server /usr/bin/
sudo install -m755 target/release/fips-pubdom /usr/bin/          # optional, for checks
sudo install -m644 packaging/systemd/fips-pubdom-server.service /etc/systemd/system/
sudo mkdir -p /etc/fips-pubdom/zones

# firewall: if you run fips's baseline firewall (fips-firewall.service, off
# by default in fips's packages), it drops everything inbound on fips0
# unless a drop-in allows it
sudo cp packaging/common/fips-pubdom.nft /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl try-reload-or-restart fips-firewall
```

Then write the zone file, add the TXT record and start the unit — the
whole procedure is in [operators.md](operators.md). To publish the claim
automatically, give the unit the extra flags through its environment file
(it is read if present, so the unit runs without it too):

```sh
echo "PUBDOM_SERVER_ARGS=--publish --relay wss://relay.example --relay ws://npub1….fips:80" \
    | sudo tee /etc/fips-pubdom/server.env
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubdom-server
systemctl status fips-pubdom-server
```

The unit runs as an unprivileged throwaway user in group `fips` (to read
the key): **one process serving every** `/etc/fips-pubdom/zones/*.yaml`, all on the same port — the node's
fips address, 5355 by default, UDP and TCP. Zones that name different
`port:` values need separate processes. A zone file added to the directory is
picked up at the next `systemctl restart fips-pubdom-server`; edits to a
loaded one are re-read on their own. With no zone file the unit stops
with "no zone files in /etc/fips-pubdom/zones" instead of retrying.

## Install: the desktop resolver

On a machine running fips whose applications should reach bound names:

```sh
sudo install -m755 target/release/fips-pubdomd target/release/fips-pubdom /usr/bin/
sudo install -m644 packaging/systemd/fips-pubdom.service /etc/systemd/system/
sudo fips-pubdomd setup                 # detects resolved / NetworkManager / dnsmasq / plain resolv.conf, writes the config
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubdom
resolvectl query peer.fips              # .fips still works
sudo fips-pubdom verify example.org     # a bound domain verifies
```

On a daemon host the CLI shares the daemon's config and therefore its pin
file under `/var/lib/fips-pubdom/`, which is root-owned: run it with `sudo`,
or give yourself a user-level config as in "the CLI only" below.

`setup` supports systemd-resolved, NetworkManager without resolved, a
standalone dnsmasq, and a plain `resolv.conf` (detected, or named with
`--backend`); with NetworkManager or a plain `resolv.conf` the daemon
listens on port 53. `setup` says when the listen addresses changed:
restart the daemon then, and after `teardown`, which restores the config. Other platforms are on
the [roadmap](roadmap.md). Everything `setup` changes is undone by `sudo
fips-pubdomd teardown`. Configuration, behaviour and troubleshooting:
[daemon.md](daemon.md).

To run the daemon without touching the OS resolver — for a look, or for
tests — give it a config with a writable pin path and explicit upstreams
(without upstreams it considers itself offline and answers SERVFAIL for
every legacy name), then query it directly:

```sh
cat > ./config.yaml <<'EOF'
pins: ./pins.json
upstreams: ["9.9.9.9", "1.1.1.1"]
EOF
fips-pubdomd --config ./config.yaml run     # listens on [::1]:5356 / 127.0.0.1:5356
dig @::1 -p 5356 www.example.org AAAA
dig @::1 -p 5356 peer.fips AAAA
```

## Install: the CLI only

`fips-pubdom` needs no service. It reads the same config as the daemon
(`/etc/fips-pubdom/config.yaml`, or `--config`), and a config with just a
`pins:` path in a writable place is enough:

```sh
install -m755 target/release/fips-pubdom ~/.local/bin/
printf 'pins: %s/.local/share/fips-pubdom/pins.json\n' "$HOME" > ~/.config/fips-pubdom.yaml
fips-pubdom --config ~/.config/fips-pubdom.yaml verify example.org
fips-pubdom --config ~/.config/fips-pubdom.yaml lookup www.example.org
fips-pubdom --config ~/.config/fips-pubdom.yaml --offline lookup www.example.org
```

`lookup` runs the full resolver path — including the mesh query through the
local fips node — and prints the answer an application would get;
`verify` prints every input to the decision without applying it.

## Upgrading

Rebuild, reinstall the binaries and the units, restart:

```sh
git pull && cargo build --release
sudo install -m755 target/release/fips-pubdom-server target/release/fips-pubdomd target/release/fips-pubdom /usr/bin/
# the units too — a fixed unit only takes effect once copied (whichever are installed):
sudo install -m644 packaging/systemd/fips-pubdom-server.service packaging/systemd/fips-pubdom.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart fips-pubdom-server fips-pubdom
```

Pins (`/var/lib/fips-pubdom/pins.json`) and the config survive upgrades;
the file format is stable within a phase.

## Uninstall

```sh
sudo systemctl disable --now fips-pubdom fips-pubdom-server
sudo fips-pubdomd teardown
sudo rm -f /usr/bin/fips-pubdom /usr/bin/fips-pubdomd /usr/bin/fips-pubdom-server
sudo rm -f /etc/systemd/system/fips-pubdom.service /etc/systemd/system/fips-pubdom-server.service
sudo rm -f /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl daemon-reload
sudo systemctl try-reload-or-restart fips-firewall
sudo rm -rf /etc/fips-pubdom /var/lib/fips-pubdom          # config, zones, server.env and pins
```

## Android

There is nothing to install from this repository: fips2go embeds the
library crates. Build fips2go as its README's "Build" section describes — the native shim with `./build-native.sh arm64-v8a`
(needs the Android NDK), then the APK from the `android/` directory with
Gradle and JDK 17 — and install it with `adb install`. The feature is on by
default under Settings → *Public domain names over fips*; relays on the
mesh go in *Mesh relays for public names* below it. Details and limits:
[android.md](android.md).

## Other platforms

The library crates build everywhere Rust does, including
`aarch64-linux-android` (CI checks). The binaries build on macOS and
Windows too, but `setup` has no backend there yet, so the daemon must be
wired in by hand (`/etc/resolver/`, `networksetup`, NRPT) — see
[platforms.md](platforms.md) for the plan.
