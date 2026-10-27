# forester-node protocol (v1)

A node holds encrypted blobs for the Forester network. It never sees file names, owners or keys, and it never accepts an operation that the control plane (CP) has not signed.

## Identity

- On first run the node creates an Ed25519 key pair in `identity.key` (mode 0600). The private key never leaves the machine.
- `nodeId = "fn_" + hex(sha256(publicKey))[0..24]`. The CP recomputes this from the public key, so ids cannot be spoofed.

## Control link

The node dials out over WebSocket to `{orchestrator}/v1/nodes/connect` (`wss://` in production), so nodes never need an open inbound TCP port. Text frames carry JSON. Binary frames carry blob data: `[rid: u32 big endian][payload]`.

Handshake:

| Direction | Message |
|---|---|
| CP → node | `{"t":"challenge","nonce":hex,"cpKey":b64url}` |
| node → CP | `{"t":"hello","nodeId","pubKey":b64url,"sig":b64url,"version","name","settings":{"personalSite":bool},"rtc":{"port":u16,"candidates":[string]}}` |
| CP → node | `{"t":"welcome","claimed":bool,"pairingCode":string\|null}` |

- `sig` signs the UTF-8 bytes `forester-node-hello:v1:{nonce}`.
- The node pins `cpKey` on first connect (trust on first use, or `FORESTER_CP_KEY`) and refuses a CP presenting a different key afterwards.
- An unclaimed node shows its pairing code. The owner enters it on the website to link the node to their account.

## Capabilities

Every CP command and every browser request carries `cap`. It's `b64url(json) + "." + b64url(ed25519_sig_by_cp(json bytes))`, where:

```json
{"v":1,"op":"put|get|del|por|rtc|settings|update","node":"fn_...","blob":"id or null","max":bytes,"exp":unix_ms}
```

The node rejects a capability when any of these holds:
- the signature fails against the pinned CP key
- `node` is not its own id
- `exp` has passed
- `op` or `blob` doesn't match the request
- a put exceeds `max`

## Operations (CP → node)

| Request | Reply |
|---|---|
| `{"t":"put","rid","blob","size","sha256","cap"}` then binary frames then `{"t":"end","rid"}` | `{"t":"ok","rid","bytes"}` or `{"t":"err","rid","error"}` |
| `{"t":"get","rid","blob","offset","length","cap"}` | `{"t":"meta","rid","size"}`, binary frames, `{"t":"end","rid"}` |
| `{"t":"del","rid","blob","cap"}` | `{"t":"ok","rid"}` |
| `{"t":"por","rid","blob","offset","length","nonce","cap"}` | `{"t":"por","rid","hash"}` where `hash = hex(sha256(nonce_bytes \|\| blob[offset..offset+length]))` |
| `{"t":"rtc","rid","sdp","cap"}` | `{"t":"rtc","rid","sdp"}` (non-trickle answer with all node candidates) |
| `{"t":"settings","rid","personalSite"?,"autoUpdate"?,"maxStorageGb"?,"reserveFreeGb"?,"name"?,"cap"}` | `{"t":"ok","rid"}` |
| `{"t":"update","rid","cap"}` | `{"t":"ok","rid","installing":version or null,"current"}` |

- **put:** the node streams the data to a temp file, verifies the size and sha256, and only then atomically renames it into place.
- **update:** the node fetches the signed release manifest and, if it is newer, stages and switches to it (see Updates). `installing` is null when it is already current.
- **por:** the CP derives expected answers when it first sees the blob, so it never needs to keep the data to verify storage later.

## Status (node → CP)

`{"t":"status","report":{...},"sig":b64url}` every 30 seconds and on change. The signature covers the exact report JSON. The report has:

- `ts`
- `allocBytes`, `usedBytes`, `blobCount`
- `diskTotal`, `diskAvailable`, `reserveBytes`
- `volumeFingerprint`, `personalSite`, `version`
- `maxStorageBytes`, `settingsLocked` (settings pinned by environment variables)
- `platform`, `autoUpdate`, `selfUpdate`, `update` (`latest`, `checkedAt`, `error`, `state`)

The CP treats the report as a claim and cross-checks it against blobs it placed and challenge results.

## Updates

`https://share.forester.dev/node/release.json` is `{"payload":string,"sig":b64url}`. The signature is Ed25519 by the Forester release key (its public key is compiled into the node) over the exact payload bytes. The payload is:

```json
{"v":1,"version":"2.1.0","publishedAt":unix_ms,"artifacts":{"linux-x86_64":{"path":"forester-node-linux-x86_64","sha256":"hex","size":bytes}}}
```

`path` is relative to the manifest URL. The node checks a few minutes after starting and then every six hours with jitter (`auto_update`, on by default), or at once on an `update` command. For a newer version it:

1. downloads the artifact for its platform into `<data_dir>/bin/`, refusing anything over the signed size or with a different sha256
2. runs it with `--version` and requires the signed version
3. refuses new transfers (`node_restarting`, so the CP uses another replica), waits up to 120 s for running ones, and execs the new build in the same process

The installed binary is never modified. On each start it verifies the staged build against the signed manifest again and execs it only when it is newer. If a staged build fails to stay up for two minutes three starts in a row, it is discarded and that version is skipped until a newer one ships.

## Browser data channel (Phase C)

Browsers open a WebRTC data channel (label `forester`) to the node. The SDP is relayed by the CP using an `rtc` capability.

- **put:** `{"op":"put","id","blob","size","sha256","cap"}`, then binary messages (up to 64 KiB each), then `{"op":"end","id"}`. The node replies `{"id","ok":true,"bytes"}` or `{"id","error"}`.
- **get:** `{"op":"get","id","blob","offset","length","cap"}`. The node replies `{"id","size"}`, then binary messages, then `{"id","done":true}`.

One transfer runs at a time per channel; browsers open several channels for parallelism. Host candidates make same-LAN transfers go direct at LAN speed.
