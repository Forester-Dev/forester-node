# forester-node

The storage node for [Forester Share](https://share.forester.dev): a file sharing and storage network that runs on computers people own instead of one company's data centre.

Run it on a machine with spare disk and it will:

- **lend that space to the network**, holding encrypted pieces of other people's files that it cannot read
- **keep your own files first**: they are stored on your disk for free and never make way for anyone else's
- **serve transfers directly**: to browsers over WebRTC, and between your own devices at local network speed when you are at home
- **prove it is really storing what it holds**, by answering random storage checks from the network (from 2.4.0, Merkle proofs against a root the network keeps, so checks never run out)
- **keep itself up to date** with signed releases, without dropping transfers in progress

It is a single static binary written in Rust, with no runtime dependencies.

> **Status: early.** The network is new and small. Nodes earn a share of storage revenue, paid monthly to a bank account in New Zealand (other countries build up earnings until payouts open there). How work is counted is in the [docs](https://share.forester.dev/docs#guide-node). Builds exist for Linux on x86_64 today; macOS, Windows and ARM are planned. See [share.forester.dev/status](https://share.forester.dev/status) for live network health.

## Install

### Linux (systemd)

```sh
curl -fsSL https://share.forester.dev/node/install.sh | sudo sh
```

The [installer](scripts/install.sh) downloads the binary, checks it against `SHA256SUMS`, installs it as a systemd service running as its own unprivileged user, and prints the pairing code. Data lives in `/var/lib/forester-node`. Re-running it upgrades in place and keeps the node's identity and settings. Read it before piping it to a shell; it is short.

### Docker (Unraid, TrueNAS, Synology, any x86_64 host)

```sh
docker run -d --name forester-node --restart unless-stopped \
  -v /path/to/your/disk:/data -p 8096:8096/udp \
  -e FORESTER_DATA_DIR=/data -e FORESTER_RTC_PORT=8096 \
  alpine:3.23 sh -c "wget -qO /usr/local/bin/forester-node https://share.forester.dev/node/forester-node-linux-x86_64 && chmod +x /usr/local/bin/forester-node && exec forester-node run"
```

Point the volume at the disk you want to lend. UDP 8096 is optional but enables direct and local-network transfers. If you would rather run an image you built yourself, see [Build from source](#build-from-source).

### Link it to your account

The node prints an 8 character pairing code on first start (`docker logs forester-node`, or `journalctl -u forester-node` with systemd). Enter it on your [Dashboard](https://share.forester.dev/dashboard) to link the node to your account. You can also print it any time:

```sh
forester-node pairing-code
```

## What your node can and cannot see

- Files are encrypted before they reach any node and split into pieces. A node holds pieces of many files and never receives file names, owners or keys.
- The node dials **out** to the network over one WebSocket, so it works behind home routers and CGNAT with **no open inbound TCP port**.
- Every instruction the node receives (store, read, delete, prove) carries a short-lived capability signed by the control plane for exactly that operation. The node pins the control plane's key on first connect and refuses anything not signed by it. See [PROTOCOL.md](PROTOCOL.md).
- Updates are only installed if signed by the Forester release key compiled into the node, with matching size and SHA-256.
- The node keeps its own Ed25519 identity in `identity.key` in its data directory. The private key never leaves the machine. Back up the data directory; don't share it.

## Settings

Settings live in `config.toml` in the data directory and are picked up within 30 seconds, no restart needed. You can also change them from the Dashboard or the command line:

```sh
forester-node config-set max_storage_gb 500     # most it may lend; unset = all free space minus the reserve
forester-node config-set reserve_free_gb 50     # always keep this much free for yourself (default 20)
forester-node config-set name "Garage NAS"
forester-node config-set auto_update false      # you can still update from the Dashboard
forester-node web-view on                       # serve your own site on port 8097 (see below)
forester-node status                            # identity, linking, disk and allocation
```

Environment variables override the file (and then cannot be changed from the Dashboard):

| Variable | Meaning |
|---|---|
| `FORESTER_DATA_DIR` | Data directory (default `/var/lib/forester-node`) |
| `FORESTER_NODE_NAME` | Display name |
| `FORESTER_MAX_STORAGE_GB` | Most space to lend, in GB |
| `FORESTER_RESERVE_FREE_GB` | Space always kept free, in GB |
| `FORESTER_RTC_PORT` | UDP port for direct transfers (0 picks a free one) |
| `FORESTER_ANNOUNCE_IPS` | Extra addresses to advertise, e.g. your LAN IP when running in Docker |
| `FORESTER_AUTO_UPDATE` | `true` / `false` |
| `FORESTER_WEB_VIEW` | `true` / `false`: serve your own site (below) |
| `FORESTER_WEB_PORT` | Port for your own site (default 8097) |
| `FORESTER_CP_KEY` | Pin the control plane key instead of trusting it on first connect |

## Your own site

Your node can serve your own transfer page on a domain you own: you send files from it, and the people you send to download there, with one link back to Forester. Turn it on with `forester-node web-view on` (or from the Dashboard); the node then serves plain HTTP on port 8097. Put a reverse proxy or tunnel in front that gives your domain HTTPS and passes the original host name, for example with Caddy:

```
files.example.com {
  reverse_proxy 127.0.0.1:8097
}
```

Then add the domain on your Dashboard. Forester asks `https://<your domain>/.well-known/forester-site` for a signature by your node's key over the domain, and only accepts the domain once it really leads to your node. The page and its scripts come from share.forester.dev over HTTPS and are cached by the node; your files never pass through this web server.

## Updates

With `auto_update` on (the default), the node checks for a new release a few minutes after starting and then every six hours. It downloads the build for its platform into `<data dir>/bin`, verifies the signature, size and checksum, runs it once to confirm the version, lets transfers in progress finish, and then switches over in the same process. systemd and Docker never see a restart. If a new build fails to stay up three times, the node goes back to the installed version and skips that release. Details are in [PROTOCOL.md](PROTOCOL.md#updates).

## Build from source

You need Rust (stable). For a fully static Linux binary:

```sh
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --locked --target x86_64-unknown-linux-musl
cargo test
```

Or build the Docker image, which compiles inside a container and runs as an unprivileged user:

```sh
docker build -t forester-node .
docker run -d --name forester-node --restart unless-stopped -v /path/to/your/disk:/data -p 8096:8096/udp forester-node
```

A node built from source works on the network like any other. Its self-update will move it to the official signed release once one newer than your build is published; set `auto_update = false` to stay on your own build.

## Contributing and security

Issues and pull requests are welcome. Please report security problems privately as described in [SECURITY.md](SECURITY.md) rather than in a public issue.

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). You can run, study, change and share the node freely. If you run a modified version as a service for other people, you must make your changes available to them under the same licence.
