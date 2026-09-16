# WireGuard session history

## Install the published image

This fork publishes `ghcr.io/cmtyomg/mikrodash:latest` for Linux amd64, ARM64 and
ARMv7. To install without a local build:

```sh
docker pull ghcr.io/cmtyomg/mikrodash:latest
docker run -d --name MikroDash --restart unless-stopped -p 3081:3081 \
  -v mikrodash_data:/data ghcr.io/cmtyomg/mikrodash:latest
```

Open `http://SERVER_IP:3081` and complete setup. The `/data` volume keeps router
settings and session history across container replacements. If a MikroDash
container already exists, update it through its existing deployment instead of
creating another container with the same name.

With this repository checked out, the equivalent Compose deployment is:

```sh
docker compose -f docker-compose.ghcr.yml pull
docker compose -f docker-compose.ghcr.yml up -d
```

Every published build also has a `sha-COMMIT` tag for pinning a specific build.

## Session collection

The VPN page records an observed history for each WireGuard public key and
interface, scoped to its router. Choose a peer in **WireGuard Session History**
to see its source IPs, start/end observations, approximate duration, uploaded and
downloaded bytes, and totals across the retained sessions. Deleted peers remain
available in the history selector until their history expires.

Recording starts automatically when MikroDash has its SQLite database and the
router's VPN collector is enabled. Normal standalone operation keeps collection
running with no browser open. The existing `-no-pool` option disables background
collection; disabling a router or its VPN collector also stops observations.
WireGuard history does not depend on the traffic/ping `-history` flag or the
router's Reports setting. It uses the existing peer poll, with no extra RouterOS
connection or command. The database is upgraded by the normal startup migration
(schema 17).

Completed sessions are kept for **90 days after their last observation**. A
minute maintenance task removes expired history independently of the general
metrics retention setting. Open sessions remain available. The database and
counter baselines persist in the application's existing `/data` volume.

## What an observed session means

WireGuard does not expose login/logout events or a connection uptime. MikroDash
considers a peer active while its latest successful handshake or an observed
increase in received bytes is less than three minutes old. Transmitted bytes
alone do not prove that the remote peer is reachable. Sessions are therefore
estimates, with timing uncertainty from that threshold and the VPN poll interval.
A quiet tunnel can be classified inactive while it is still configured on a
client, and reconnects entirely between polls cannot always be distinguished.

The source IP comes exclusively from `current-endpoint-address`, the source of
authenticated packets. A configured `endpoint-address` is not evidence of an IP
actually used. Both IPv4 and IPv6 are supported. A change in source IP produces
another observation; a NAT source-port change alone does not.

Upload means bytes received by the router from the peer (RX); download means
bytes sent by the router to the peer (TX). These are changes in the RouterOS
WireGuard counters. They are not application-level billing measurements.

The first sample establishes a baseline: existing lifetime counters are not
assigned to a new session. IP changes, counter resets, peer removal, and gaps of
more than 90 seconds in successful polling close the previous observation.
Unknown boundary traffic is excluded and the row is marked **Partial observation**.
The end of a monitoring gap is never presented as a known disconnection time:
duration stops at the last observed sample. Short application restarts can
continue the saved baseline; longer interruptions produce a monitoring gap.
History before this feature starts collecting cannot be reconstructed.

## Read API

`GET /api/vpn/wireguard/sessions?routerId=...&peer=...&limit=50&offset=0`

`peer` is an optional public key. Limits are 1–200, default 50. The response
contains `sessions`, peer filter options, totals (`rx`, `tx`, `total` sessions),
the last successful poll timestamp, and `retentionDays`. Totals cover all retained
sessions matching the filter, not just the page. Timestamps are Unix milliseconds.
Read access to the VPN page on the requested router is required. Responses are
not cached.
