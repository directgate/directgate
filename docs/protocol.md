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
- `cmd`: `action` (start/stop), `status`, `reason`
- `resize`: `rows`, `cols`, `width`, `height`
- `webrtc`: `sdp` (SDP string), `candidate`, `sdpMid`
- `file/start`: `transferId`, `name`, `size` (decimal string), `chunks`, `chunkSize`
- `file/chunk`: `transferId`, `index`, binary payload
- `file/end`: `transferId`, `sha256`
- `file/ack`: `transferId`, `index`
- `file/cancel`: `transferId`, `reason`

> **Note:** File size is serialized as a decimal string to cleanly handle files larger than 4 GB.

## See also

- [File transfer & remote file manager](file-manager.md) - the `manager` and `file` message types in detail
- [Security model](security.md) - how the `encrypted` envelope and continuity counter work
