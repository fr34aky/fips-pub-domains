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

- **Rust** (stable, 1.88 or newer for let-chains):
  `curl https://sh.rustup.rs -sSf | sh` on Linux/macOS, or the distribution
  package (`rust`/`cargo` on Arch, Debian ≥ 13, Fedora; older Debian/Ubuntu
  packages are too old — use rustup).
- **git**, to clone.
- **fips** installed and running on the machine — both roles talk to the
  local node: the server binds the node's fips address, the daemon asks
  fips's `.fips` responder (`[::1]:5354`) and routes through the node's TUN.
- For the server: read access to the node key. With fips's packages the key
  is `/etc/fips/fips.key`, mode 640, group `fips` — add the serving user to
  that group (`sudo usermod -aG fips $USER`, re-login) or run the unit,
  which does it for you.

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

Run the tests with `cargo test --workspace` — 50 tests, no network needed.

## Install: the domain server

On the node that serves the domain:

```sh
sudo install -m755 target/release/fips-pubdom-server /usr/bin/
sudo install -m755 target/release/fips-pubdom /usr/bin/          # optional, for checks
sudo install -m644 packaging/systemd/fips-pubdom-server.service /etc/systemd/system/
sudo mkdir -p /etc/fips-pubdom/zones

# firewall: fips's baseline drops everything inbound on fips0 unless allowed
sudo cp packaging/common/fips-pubdom.nft /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl reload fips-firewall
```

Then write the zone file, add the TXT record and start the unit — the
whole procedure is in [operators.md](operators.md). To publish the claim
automatically, add `--publish --relay wss://…` to the unit's `ExecStart`
(`sudo systemctl edit fips-pubdom-server`) or run `fips-pubdom-server
publish` by hand.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubdom-server
systemctl status fips-pubdom-server
```

The unit runs as group `fips` (to read the key), one process for every
`/etc/fips-pubdom/zones/*.yaml`, listening on the node's fips address port
5355 (UDP and TCP).

## Install: the desktop resolver

On a machine running fips whose applications should reach bound names:

```sh
sudo install -m755 target/release/fips-pubdomd target/release/fips-pubdom /usr/bin/
sudo install -m644 packaging/systemd/fips-pubdom.service /etc/systemd/system/
sudo fips-pubdomd setup                 # systemd-resolved: writes the config and the drop-in
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubdom
resolvectl query peer.fips              # .fips still works
fips-pubdom verify example.org          # a bound domain verifies
```

`setup` currently supports systemd-resolved (Ubuntu, Fedora, Arch, Debian
with resolved); other backends are on the [roadmap](roadmap.md). Everything
`setup` changes is undone by `sudo fips-pubdomd teardown`. Configuration,
behaviour and troubleshooting: [daemon.md](daemon.md).

To run the daemon without touching the OS resolver — for a look, or for
tests — start it on loopback and query it directly:

```sh
fips-pubdomd --config ./config.yaml run     # listens on [::1]:5356 / 127.0.0.1:5356
dig @::1 -p 5356 www.example.org AAAA
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

Rebuild, reinstall the binaries, restart the units:

```sh
git pull && cargo build --release
sudo install -m755 target/release/fips-pubdom-server target/release/fips-pubdomd target/release/fips-pubdom /usr/bin/
sudo systemctl restart fips-pubdom-server fips-pubdom     # whichever are installed
```

Pins (`/var/lib/fips-pubdom/pins.json`) and the config survive upgrades;
the file format is stable within a phase.

## Uninstall

```sh
sudo systemctl disable --now fips-pubdom fips-pubdom-server
sudo fips-pubdomd teardown
sudo rm -f /usr/bin/fips-pubdom{,d,-server} /etc/systemd/system/fips-pubdom{,-server}.service /etc/fips/fips.d/fips-pubdom.nft
sudo systemctl daemon-reload && sudo systemctl reload fips-firewall
sudo rm -rf /etc/fips-pubdom /var/lib/fips-pubdom          # config, zones and pins
```

## Android

There is nothing to install from this repository: fips2go embeds the
library crates. Build fips2go's `names` branch (`./build-native.sh
arm64-v8a`, then `gradle assembleDebug` — see fips2go's own CLAUDE.md for
the toolchain) and install the APK; the feature is on by default under
Settings → *Public domain names over fips*. Details and limits:
[android.md](android.md).

## Other platforms

The library crates build everywhere Rust does, including
`aarch64-linux-android` (CI checks). The binaries build on macOS and
Windows too, but `setup` has no backend there yet, so the daemon must be
wired in by hand (`/etc/resolver/`, `networksetup`, NRPT) — see
[platforms.md](platforms.md) for the plan.
