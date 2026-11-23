[Back to README](../README.md)

# Protocol specification

DirectGate uses a custom binary framing over WebSocket frames and the WebRTC data channel. Each message consists of:

1. **Length prefix** (4 bytes, little-endian): size of the JSON header
2. **JSON header**: message metadata and type information
3. **Binary payload** (optional): raw data following the header

## Message types

| Type        | Direction                | Purpose                                            |
|-------------|--------------------------|----------------------------------------------------|
| `role`      | Agent/Client -> Server   | Register with the device ID                        |
| `auth`      | Client <-> Agent         | SRP-6a authentication                              |
| `cmd`       | Client -> Agent          | Control commands (start, stop)                     |
| `data`      | Bidirectional            | Terminal I/O (E2E encrypted)                       |
| `resize`    | Client -> Agent          | Terminal dimension changes                         |
| `status`    | Server -> Client/Agent   | Session status notifications                       |
| `error`     | Any -> Any               | Error notifications                                |
| `webrtc`    | Client <-> Agent (relay) | P2P signaling: offer / answer / ice                |
| `file`      | Bidirectional            | Chunked file transfer                              |
| `manager`   | Client <-> Agent         | Remote file manager (list, search, mkdir, rename)  |
| `admin`     | Client -> Agent          | Administrative ops (e.g. `add-key`)                |
| `exec`      | Client <-> Agent         | A non-interactive command: start, input, signal, output, exit |
| `verify`    | Server <-> Agent         | Enrollment / token-update acknowledgement          |
| `keepalive` | Bidirectional            | Connection keepalive                               |
| `encrypted` | Client <-> Agent         | E2E envelope carrying an inner wire-format message |

## Header fields

Common fields present in all message headers:

- `version`: protocol version number (currently `1`)
- `type`: message type identifier
- `action`: sub-type or operation (e.g. `start`, `chunk`, `offer`, `answer`)
- `sessionId`: unique identifier assigned by the signaling server
- `payloadSize`: size of the binary payload in bytes (when present)
- `encrypted`: boolean - payload is E2E encrypted when true
- `cc`: continuity counter (uint32, starts at 1 after auth; strictly monotonic per session/direction)

Type-specific fields:

- `role`: `role` (agent/client), `id` (pairing identifier)
- `auth`: SRP handshake metadata (`user`, `A`, `B`, `salt`, `nonce`, `suite`, `M1`, `M2`, `status`, `reason`). The `M1`/`M2` transcript binds both `nonce` values, so nonce tampering fails authentication (see [Security](security.md#srp-6a-authentication))
- `auth` with `method=key`: a host whose operator allowed managed keys for its organization (`auth.key.managedOrganizationId`) also accepts the keys of its current managed-key lease, next to its local authorized keys; a device with neither answers `key auth not configured`. A managed key is checked at the hello and again after the proof (`client not authorized` when the lease dropped it in between). A session authenticated only by a managed key is closed when the lease drops the key, expires or changes organization
- `auth` with `action=resume`: on a new relay socket, a client asks for a lost desktop session back (`resumeSid`, and a `proof` sealed with that session's keys). A host that can resume says so with `resume: true` on its `auth/result`; on a valid proof the session carries on under the new socket's id, keys, counters and data channel unchanged, and the host answers `ok` with `resumed: true` and a sealed `proof` of its own. Anything else is answered `failed` and the client authenticates afresh (see [Session Resume](../../docs/protocol.md#session-resume))
- `cmd`: `action` (start/stop), `mode` (`terminal`, `file-manager`, `desktop`, `exec`), `status`, `reason`
- `auth/result`: `exec: true` when the host runs non-interactive commands; a client asks only such a host for `mode: "exec"`
- `exec/start`: `command`, optional `cwd`, `timeoutMs`, `outputMax` (bytes of each stream to send), `stdin`; answered by `exec/started` (`status`, `pid` or `reason`)
- `exec/input` (payload), `exec/eof`, `exec/signal` (`signal`: `INT`, `TERM`, `KILL`, `HUP`)
- `exec/output`: `stream` (`stdout` / `stderr`), payload; `exec/exit`: `exitCode`, optional `signal`, `timedOut`, `truncated` (see [`exec`](../../docs/protocol.md#exec))
- `status`: `status` (`closed`), and from the relay to the host an optional `reason`: `lost` when the client's socket went away without the relay ending the session. A host keeps an authenticated desktop whose data channel is up for at most 60 s after a `lost` notice, or after its own relay link drops, and ends it at once on a plain `closed` (see [Detached desktop sessions](../../docs/protocol.md#detached-desktop-sessions))
- `resize`: `rows`, `cols`, `width`, `height`
- `webrtc`: `sdp` (SDP string), `candidate`, `sdpMid`
- `file/start`: `transferId`, `name`, `size` (decimal string), `chunks`, `chunkSize`
- `file/chunk`: `transferId`, `index`, binary payload
- `file/end`: `transferId`, `sha256`
- `file/ack`: `transferId`, `index`
- `file/cancel`: `transferId`, `reason`
- `admin`: a session authenticated only by a managed key gets `admin-result`
  `error` / `managed key cannot perform admin actions` for every action,
  `add-key` and temporary desktop shares included

> **Note:** File size is serialized as a decimal string to cleanly handle files larger than 4 GB.

## See also

- [File transfer & remote file manager](file-manager.md) - the `manager` and `file` message types in detail
- [Security model](security.md) - how the `encrypted` envelope and continuity counter work
