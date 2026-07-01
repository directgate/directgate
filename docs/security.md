[Back to README](../README.md)

# Security model

DirectGate implements a layered security architecture. Because the agent is the component that runs on your machine, the cryptography below is exactly what you can audit in this repository.

For additional detail about the threat model, trust assumptions, and frequently asked questions, see [directgate.io/security](https://directgate.io/security).

## Transport Layer Security (TLS/SSL)

All WebSocket connections use WSS (WebSocket Secure). This provides:

- Encrypted signaling channels between all components
- Server certificate verification
- Protection against man-in-the-middle attacks at the transport level

## WebRTC data channel (DTLS)

The WebRTC data channel is secured with DTLS (Datagram Transport Layer Security), providing transport-level encryption for the P2P link. Because WebRTC signaling (offer, answer, ICE candidates) is exchanged over the authenticated E2E channel after SRP authentication, embedded DTLS fingerprints are integrity-protected. This prevents relay-level or network-level manipulation of peer identity during negotiation.

## End-to-end encryption (AES-256-SIV)

Terminal data exchanged between agent and client is encrypted end-to-end using AES-256-SIV at the application layer, independent of transport. The keys are derived from the SRP session key via HKDF-SHA256, using the agent nonce, client nonce, and agent ID as context. Using both nonces in the derivation ensures session freshness and prevents either side from unilaterally determining the resulting encryption keys. Separate keys are derived for each direction, so traffic sent by the agent and traffic sent by the client are protected with different encryption keys.

All post-authentication traffic is protected by authenticated encryption. Each packet includes a strictly monotonically increasing continuity counter that is authenticated and incorporated into the AES-SIV computation. The counter starts at 1 for each session and increments with every encrypted packet, providing replay protection while also ensuring that packet uniqueness does not depend solely on nonce uniqueness.

DirectGate additionally generates a fresh cryptographically secure random nonce for every encrypted packet. The combination of per-packet nonces and authenticated packet metadata helps prevent ciphertext repetition across otherwise identical messages. AES-SIV was chosen because it is nonce-misuse resistant by design: accidental nonce reuse does not result in the catastrophic confidentiality failures associated with conventional nonce-based AEAD modes such as AES-GCM. The design does not rely on any single mechanism for uniqueness or replay protection; packet counters, authenticated metadata, per-packet nonces, and AES-SIV's nonce-misuse resistance provide multiple independent layers of protection.

This ensures:

- The relay cannot access plaintext terminal data even when forwarding it
- The relay cannot access signaling messages, including SDP offers, answers, ICE candidates, and DTLS fingerprints
- Only the paired agent and client can decrypt session data - the relay has zero knowledge of payload contents
- End-to-end encryption is preserved across both the WebSocket relay path and the WebRTC P2P path
- Session integrity is maintained end-to-end regardless of the underlying transport
- Replay attacks, reflected packets, message tampering, payload modification, and transport-level manipulation are mitigated

## SRP-6a authentication

Authentication uses SRP-6a (Secure Remote Password). No password is ever transmitted in any form:

1. Client sends SRP public value `A` and client `nonce` (`auth/hello`)
2. Agent responds with `salt`, `B`, agent `nonce`, and credential `suite` (`auth/challenge`)
3. Client sends SRP proof `M1` (`auth/proof`)
4. Agent verifies `M1`, replies with `M2` (`auth/result`)
5. Client verifies `M2` before enabling encryption
6. Both sides derive E2E keys from the SRP session key `K` via HKDF-SHA256
7. On success: agent starts the PTY, client enables encrypted terminal I/O

The credential `suite` (advertised in `auth/challenge`) pins both the `x` derivation and the proof transcript. Under the current suite (`1`), the agent and client nonces are folded into the `M1`/`M2` transcript in addition to seeding the E2E HKDF salt. Because the nonces are now covered by the mutually verified proof, a relay that tampers with either nonce in transit is rejected at authentication - it can no longer silently force the two sides to derive mismatched keys. The agent, the native client, and the browser client all require this exact suite; there is no legacy fallback, so a device enrolled under an earlier scheme must re-run SRP password setup to regenerate its credential.

After step 6, the client initiates WebRTC P2P negotiation in parallel with the active terminal session. The P2P link uses DTLS-secured WebRTC data channels for transport, and the payload is additionally protected by AES-256-SIV using keys derived from the SRP session key.

## Key-based authorization (optional)

In addition to SRP, the agent supports Ed25519 key authorization. The agent holds an identity keypair (`agentIdentity`) and a list of `authorizedKeys`; clients can be authorized by public key, and new keys can be added at runtime over the authenticated channel (`admin/add-key`), just like `ssh-copy-id` does. See [Configuration](configuration.md).

## Relay-visible metadata

End-to-end encryption protects payload contents, not routing metadata. The relay necessarily sees the device ID / routing key used to pair endpoints, source IP addresses, connection timing, and traffic volume carried through the relay. This metadata exposure is inherent to the relay design; "zero knowledge" refers to terminal, file, editor, and signaling payload contents.

## Unencrypted control messages

A limited number of operational control messages are intentionally excluded from the session-level end-to-end encryption scheme. Relay-generated messages such as errors, status updates, disconnect notifications, and verification acknowledgements cannot be end-to-end encrypted because the relay does not possess the session encryption keys.

The `verify` protocol is connection-level authorization traffic exchanged directly between the agent and relay. The agent sends `verify/update` when its relay access token is refreshed, and the relay responds with `verify/ack`. Because `verify/update` contains an access token, its confidentiality depends on the TLS-protected `wss://` connection.

These operational messages do not contain terminal output, file contents, session encryption keys, or other end-to-end session data. A compromised relay may forge, drop, or modify them, but their effects are limited to authorization failure, incorrect status reporting, or denial of service. A compromised relay already has the ability to delay packets or terminate connections.

## Operational checklist

- **TLS encryption** - all WebSocket connections use WSS
- **WebRTC DTLS** - the P2P data channel is additionally secured by DTLS
- **End-to-end encryption** - terminal data, file contents, and editor data is AES-256-SIV encrypted between agent and client; neither the relay nor any intermediary can access plaintext
- **SRP-6a auth** - password proof exchange without ever sending the plaintext password
- **Continuity counter** - each encrypted packet carries a monotonic counter to prevent replay attacks
- **Zero-knowledge payloads** - in relay mode, the server is cryptographically incapable of decrypting session data, but necessarily sees the routing and traffic metadata described above
- **P2P bypass** - when the WebRTC channel is active, terminal data does not pass through the relay at all
- The agent allows to set any password you want and it is up to you to use strong passwords for SRP credentials (according to NIST, 15+ characters is recommended)
- Review the `shell.user` permissions in the agent configuration - the agent grants shell access as that user
- Keep the agent updated through the package repositories (or build from source) so you receive security fixes

## Cloud side

The cloud side - account management, device pairing, and the signaling/relay service is operated by [directgate.io](https://directgate.io) and is not part of this repository. Using the hosted web client requires trust in that service, as with any SaaS platform; the agent's job is to make sure the relay never sees your plaintext.

## Read more about security

Visit [directgate.io/security](https://directgate.io/security) for the threat model and FAQ.

## Reporting security issues

If you find a security issue, please report it to [security@directgate.io](mailto:security@directgate.io).