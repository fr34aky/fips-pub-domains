# Packaging

Mirrors fips's own `packaging/` layout so the two never touch each other's
files (docs/plan-platforms.md §7).

- `systemd/fips-names.service` — the resolver daemon (`fips-namesd run`).
  Wire the OS first: `sudo fips-namesd setup` (systemd-resolved backend:
  writes `/etc/fips-names/config.yaml` and
  `/etc/systemd/resolved.conf.d/fips-names.conf`). Undo with
  `sudo fips-namesd teardown`.
- `systemd/fips-names-server.service` — the domain server, one process for
  every zone in `/etc/fips-names/zones/*.yaml`, on the node's fips address.
- `common/fips-names.nft` — fips firewall drop-in allowing the server's
  port on `fips0`: `sudo cp common/fips-names.nft /etc/fips/fips.d/ &&
  sudo systemctl reload fips-firewall`.

Other platforms (launchd, Windows service, rc.d, OpenWrt) follow in later
milestones.
