[Back to README](../README.md)

# Architecture

DirectGate has three pieces. Only the first one lives in this repository.

- **Agent** (`directgate`, this repo) - runs on your machine. It performs authentication, spawns a PTY with an interactive shell, encrypts all traffic end-to-end, serves the remote file manager, and establishes a direct WebRTC data channel to the client.
- **Relay / signaling** - operated by directgate.io. It pairs agents and clients by identifier, relays the authentication and WebRTC signaling traffic, and forwards encrypted payloads when a direct P2P link is not possible. It is never able to read terminal, file manager, or code editor data. It is **not** part of this repository.
- **Client** - the web client at directgate.io (recommended), or the experimental `dgcli` CLI in this repo. The client authenticates with the agent and renders the terminal, file manager, and editor.

After authentication, the client and agent automatically negotiate a WebRTC peer-to-peer data channel. Once it is open, all terminal I/O and file transfers flow **directly between the two peers**, bypassing the relay entirely.

## Transport diagrams

**WebSocket relay (used for signaling and as fallback):**

```
+--------------+              +-----------------+              +--------------+
|   DG agent   | <-- WSS -->  |  directgate.io  |  <-- WSS --> |    Client    |
|    (PTY)     |              | (relay/signal)  |              | (web / CLI)  |
+--------------+              +-----------------+              +--------------+
       ^                                                              ^
       |                     End-to-End Encryption                    |
       +--------------------------------------------------------------+
```

**WebRTC P2P (preferred, established after authentication):**

```
+--------------+              +-----------------+              +--------------+
|   DG agent   | <-- WSS -->  |  directgate.io  |  <-- WSS --> |    Client    |
|    (PTY)     |              |   (signaling)   |              | (web / CLI)  |
+--------------+              +-----------------+              +--------------+
       ^                                                              ^
       |            WebRTC Data Channel (direct P2P)                  |
       +--------------------------------------------------------------+
          (DTLS transport + AES-256-SIV application-layer encryption)
```

Once the WebRTC data channel is established, the relay no longer carries terminal data or file transfers. It continues to handle signaling and session management but is completely removed from the data path.

## Process model on Windows

Windows is the one platform where the agent is not a single process. POSIX drops privileges with `setuid`; Windows has no equivalent, so the split is made with processes instead:

```
[ directgate-agent service ]  LocalSystem, session 0
        |
        |  launcher: acquires shell.user's logon token (passwordless, WTSQueryUserToken)
        |
        +--> [ agent ]         shell.user, medium integrity, session N, winsta0\Default
        |       protocol parsing, PTY, file manager, capture, input - everything untrusted
        |
        +--> [ desktop helper ] SYSTEM, session N, follows the input desktop
                on demand, only while a desktop session is live: reaches the UAC
                secure desktop and higher-integrity windows, which a medium-integrity
                process cannot. Parses nothing but fixed-size records from the agent.
```

The launcher and the agent talk over two anonymous pipes the agent inherits at spawn; the agent and the helper over unnamed objects the launcher mints and duplicates into both. Nothing is registered in the object namespace, so no other process can address any of it. See [Elevated UI and the secure desktop](windows.md#elevated-ui-and-the-secure-desktop) for what the helper is for and [Security model](security.md#privileged-ui-on-windows) for what it costs.

## Multiplexed PTY sessions

DirectGate supports multiple concurrent PTY sessions over a single WebSocket or WebRTC connection. During authentication, the signaling server assigns each client a unique `sessionId`. All protocol messages carry this identifier, allowing the agent to route encrypted traffic to the correct PTY instance without opening additional transport connections. This provides:

- Reduced connection overhead
- Better scalability under high session counts
- Efficient use of a single WebRTC data channel

## See also

- [Security model](security.md) - cryptography, authentication, and trust assumptions
- [WebRTC P2P & connectivity](webrtc.md) - ICE/TURN, NAT traversal, and fallback tiers
- [Protocol specification](protocol.md) - framing, message types, and header fields
