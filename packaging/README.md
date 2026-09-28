# Packaging

Mirrors fips's own `packaging/` layout so the two never touch each other's
files ([../docs/platforms.md](../docs/platforms.md)).

- `systemd/fips-pubdom.service` — the resolver daemon (`fips-pubdomd run`).
  Wire the OS first: `sudo fips-pubdomd setup` (systemd-resolved backend:
  writes `/etc/fips-pubdom/config.yaml` and
  `/etc/systemd/resolved.conf.d/zz-fips-pubdom.conf`). Undo with
  `sudo fips-pubdomd teardown`. See [../docs/daemon.md](../docs/daemon.md).
- `systemd/fips-pubdom-server.service` — the domain server: one process
  serving every zone in `/etc/fips-pubdom/zones/*.yaml` on the node's fips
  address, as group `fips` so it can read the node key; extra `serve` flags
  (`--publish --relay …`) come from `PUBDOM_SERVER_ARGS` in the optional
  `/etc/fips-pubdom/server.env`. See [../docs/operators.md](../docs/operators.md).
- `common/fips-pubdom.nft` — fips firewall drop-in allowing the server's
  port on `fips0`: `sudo cp common/fips-pubdom.nft /etc/fips/fips.d/ &&
  sudo systemctl try-reload-or-restart fips-firewall`.

launchd, Windows service, rc.d and OpenWrt packaging follow the daemon
backends for those platforms ([../docs/roadmap.md](../docs/roadmap.md)).
