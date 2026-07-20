[Back to README](../README.md)

# WebRTC P2P & connectivity

## How it works

After the client successfully authenticates with the agent, it automatically initiates WebRTC peer-to-peer negotiation:

1. **Client creates a PeerConnection** and a data channel named `"directgate"`
2. libdatachannel **auto-generates an SDP offer** when the data channel is created
3. The offer is **relayed to the agent** (wrapped in a `webrtc/offer` message)
4. The agent **creates an answer** and sends it back via `webrtc/answer`
5. ICE candidates are exchanged via `webrtc/ice` messages through the relay
6. Once both sides complete ICE negotiation, the **data channel opens**
7. From this point on, all terminal I/O and file transfers flow **directly between peers**
8. ICE negotiation happens only after authentication, and all traffic remains end-to-end encrypted

## ICE/TURN server configuration

For NAT traversal behind symmetric NATs you typically need a TURN server. **By default, DirectGate's own managed TURN servers are used** - there is nothing to set up, and it works out of the box (subject to a fair-use quota on your account).

If you would rather **opt out of that quota** and use your own infrastructure, add your TURN servers in your account settings on [directgate.io](https://directgate.io) - you still do not edit anything on the agent. The API delivers your configured ICE servers to the agent inside the enrollment response, and refreshes them on every token refresh, so changes you make in the dashboard are picked up automatically the next time the agent connects.

The agent selects ICE servers in this order:

1. **ICE servers delivered by the API** - by default these are DirectGate's managed TURN servers; if you add your own in settings, those are sent instead.
2. **A local `iceServers` array** in the agent config - a manual override, useful for debugging:

   ```json
   {
     "iceServers": [
       "stun:stun.cloudflare.com:3478",
       "turn:username:password@turn.example.com:3478"
     ]
   }
   ```

3. **Built-in defaults** (`stun:stun.cloudflare.com:3478` and `stun:stun.l.google.com:19302`) when neither of the above is present.

TURN server URLs follow the format `turn:user:pass@agent:port`. Up to **8** ICE servers can be used.

## Fallback

The connection degrades gracefully through three tiers, and the client always shows which one is active:

1. **Direct P2P** - a direct peer-to-peer WebRTC data channel. The client shows the **P2P** icon.
2. **TURN** - if a direct path cannot be established (e.g. symmetric NAT), WebRTC relays through a TURN server. It is still an end-to-end-encrypted WebRTC data channel, just routed via TURN; the client replaces the P2P icon with a **TURN** icon.
3. **WebSocket relay** - if WebRTC cannot connect at all (even via TURN), the session transparently falls back to the WebSocket relay path through directgate.io, and the icon disappears. End-to-end encryption is preserved, and the relay still cannot decrypt.

The terminal session stays fully functional on every tier, and traffic remains end-to-end encrypted regardless of which one is in use - so you always know whether the connection is direct, TURN-relayed, or on the WebSocket relay.

## Desktop video track

Desktop sessions reuse the same authenticated WebRTC connection but add a send-only H.264 **media track** (host -> browser) on top of the `directgate` DataChannel. Negotiation happens only after SRP/key-auth succeeds and the browser starts a `desktop` session. The browser offer carries:

- the existing ordered `directgate` DataChannel (encrypted DirectGate binary protocol)
- a recv-only video transceiver that advertises H.264

When the active session mode is `desktop`, the agent answers with an H.264 send-only track. The capture backend emits Annex-B H.264 access units (ScreenCaptureKit + VideoToolbox on macOS; X11 XShm capture + a runtime-loaded [Cisco OpenH264](https://github.com/cisco/openh264) encoder on Linux; DXGI Desktop Duplication + a Media Foundation encoder on Windows), and the agent packetizes them as RTP and sends them through libdatachannel's Track API (`rtcAddTrackEx` / `rtcSendMessage`). The browser renders the remote `MediaStreamTrack` in a `<video>` element. On Linux the OpenH264 library is dlopen'd at session start (`DIRECTGATE_OPENH264_LIB` overrides the search path); when it is missing - or the X11 pixel format is unsupported - the agent demotes the session to the raw-RGBA pipeline and reports the reason in the desktop status `fallbackReason` field. On Windows the agent prefers the GPU vendor's hardware H.264 encoder (Quick Sync / NVENC / AMF, whichever MFT the driver registered) and falls back to the Microsoft software encoder; `mfplat.dll` is loaded at runtime, so N editions without the Media Feature Pack demote to raw RGBA the same way (see [Desktop streaming on Windows](windows.md#desktop-streaming)).

The media track is tuned for interactive latency rather than smooth playback. The agent chains an RTCP NACK responder onto the track, so packet loss is repaired by retransmission instead of escalating to a PLI and a full
keyframe; GOPs are long (10s) because IDR frames are ordered on demand via PLI / `request-keyframe` anyway. An adaptive bitrate controller consumes the browser's RTCP receiver reports (fraction lost) - and transport backpressure on the DataChannel fallback - stepping the encoder rate down 25% on congestion and recovering toward the preset target after ~5 clean seconds (the live rate is reported as `bitrateKbps` in the desktop status). The browser side requests a zero-length jitter buffer (`jitterBufferTarget`) on the video receiver.

The pipeline degrades in this order, and the desktop status payload reports which one is active:

1. `webrtc-video` - preferred H.264 RTP over the WebRTC media track, encrypted by DTLS-SRTP
2. `h264-datachannel` - `desktop-frame-encoded` H.264 chunks over the AES-SIV-encrypted DataChannel
3. `raw-rgba` - `desktop-frame-chunk` raw frames (debug / legacy fallback)

Desktop input, control, status, terminal, file-manager, and file-transfer messages all stay on the encrypted DirectGate protocol over the DataChannel. TURN relays forward only encrypted WebRTC media/DataChannel packets - they never see plaintext desktop video or control messages.

Desktop status is a `type: "data"` packet with `payloadType: "desktop-status"` and a JSON payload; key fields are `status`, `pipeline`
(`webrtc-video` / `h264-datachannel` / `raw-rgba`), `codec`, `preset`
(`quality` / `balanced` / `low-latency`), `fps`, `bitrateKbps`, `transport`
(`dtls-srtp` for the media track, `aes-siv-datachannel` for DataChannel fallbacks), an optional `fallbackReason`, and the audio fields `audio`
(`off` / `capturing` / `unavailable`) with an optional `audioReason`.

## Desktop audio track

Desktop sessions can also carry the host's **system output audio** as a second send-only **Opus media track** on the same peer connection. It is strictly additive to the video track and shares its security and latency model: the same DTLS-SRTP transport (TURN relays still see only ciphertext), the same manual RTP packetization (`rtcAddTrackEx` with `RTC_CODEC_OPUS` / `rtcSendMessage`), and the same `msid` (`directgate-desktop`) so the browser groups audio and video into one `MediaStream` and plays both from the `<video>` element.

The browser offer adds a **recv-only Opus audio transceiver** alongside the video one; when the session mode is `desktop` the agent answers with a matching send-only Opus track. Audio and video are independent - a missing or unopened audio track never blocks the answer, the video pipeline, or the background TURN->P2P upgrade (audio rides through promotion but never gates it).

Audio is **opt-in**. The track is negotiated up front so the viewer can unmute instantly, but the host does not capture anything until the browser sends a `desktop-control` `{ "action": "audio", "enabled": true }` message; `enabled: false` stops capture. Capture runs on a dedicated thread (48 kHz stereo, 20 ms frames, ~128 kbps Opus with in-band FEC) and the encoded frames are drained onto the main loop and sent over the track, so audio never gates the video encode.

The source is always the default output device's loopback. Linux captures the PulseAudio / PipeWire default-sink monitor (`libpulse` dlopen'd, the `@DEFAULT_MONITOR@` special device, or the `DIRECTGATE_AUDIO_SOURCE` override); the Windows (WASAPI loopback) and macOS (ScreenCaptureKit audio) capture backends reuse the same orchestration and are being rolled out next. The Opus encoder is `libopus`, dlopen'd at session start (`DIRECTGATE_OPUS_LIB` overrides the search). When the encoder or the capture source is unavailable, audio reports `audio: "unavailable"` with an `audioReason` and the video stream is untouched.

## See also

- [Architecture](architecture.md) - how the agent, relay, and client fit together
- [Configuration](configuration.md) - the `iceServers` config field
