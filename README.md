![C](https://img.shields.io/badge/language-C-blue)
[![GPLv3 License](https://img.shields.io/badge/License-GPLv3-brightgreen.svg?)](https://github.com/directgate/directgate/blob/main/LICENSE)
[![Linux](https://github.com/directgate/directgate/actions/workflows/linux.yml/badge.svg)](https://github.com/directgate/directgate/actions/workflows/linux.yml)
[![MacOS](https://github.com/directgate/directgate/actions/workflows/macos.yml/badge.svg)](https://github.com/directgate/directgate/actions/workflows/macos.yml)
[![Valgrind](https://github.com/directgate/directgate/actions/workflows/tests.yml/badge.svg)](https://github.com/directgate/directgate/actions/workflows/tests.yml)
[![Sanitizers](https://github.com/directgate/directgate/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/directgate/directgate/actions/workflows/sanitizers.yml)
[![CodeQL](https://github.com/directgate/directgate/actions/workflows/codeql.yml/badge.svg)](https://github.com/directgate/directgate/actions/workflows/codeql.yml)

<div align="center">

# DirectGate

### Your devices. Accessible everywhere. Exposed nowhere.

</div>

DirectGate gives you a full terminal, file manager, and code editor on your own machines from any browser - over connections that are end-to-end encrypted and, whenever possible, peer-to-peer. Nothing listens on the public internet. No static IP required, no VPN to run and no port to forward.

This repository is the **agent**: the program you install on a machine you want to reach. It is the only part of DirectGate that runs on your hardware and touches your shell, so it is open source. You can read every line, audit the cryptography, and build it yourself to confirm that the binary you run is exactly this code.

**What it does:**

- Works behind NAT - no port forwarding, no firewall changes, no static IP
- End-to-end encrypted (AES-256-SIV) at the application layer, independent of transport
- Peer-to-peer over WebRTC whenever possible; the relay never sees plaintext
- Terminal, file manager, and a browser-based code editor over a single connection
- Multiple concurrent sessions multiplexed over one link
- Full file manager experience with upload/download, rename, copy, move, and delete
- Advanced file search, image/video playback, and drag-and-drop between devices

## Screenshots

These are the experiences the agent powers once it is paired with your account.

<table align="center">
  <tr>
    <td align="center">
      <img src="misc/screens/workspace-split.png" alt="Split workspace: terminal, file manager, AI assistant and live agent logs" width="900" />
      <br /><sub>A customizable window manager with multiple sessions in one workspace tab. Terminals, file managers, and code editors - each showing its own transport mode (P2P, TURN, or relayed) and end-to-end encryption status.</sub>
    </td>
  </tr>
</table>

<table align="center">
  <tr>
    <td align="center" valign="top" width="50%">
      <img src="misc/screens/mobile-terminal.jpg" alt="Mobile terminal" width="250" />
      <br /><sub><b>Mobile terminal</b> - a full PTY session in the phone browser, with <b>P2P</b> and <b>E2E</b> badges.</sub>
    </td>
    <td align="center" valign="top" width="50%">
      <img src="misc/screens/mobile-file-manager.jpg" alt="Mobile file manager" width="250" />
      <br /><sub><b>Mobile file manager</b> - browse and manage remote files from your phone.</sub>
    </td>
  </tr>
</table>

<table align="center">
  <tr>
    <td align="center">
      <img src="misc/screens/code-editor.png" alt="Browser-based code editor" width="760" />
      <br /><sub><b>Code editor</b> - edit files on the remote machine directly from the browser.</sub>
    </td>
  </tr>
</table>

## Quick start

1. Install the agent - see [Installation](#installation).
2. Sign in at [directgate.io](https://directgate.io), add a device, and run the pairing command it shows you on the machine where the agent is installed:

   ```bash
   directgate -sed <device_id> -t <pairing_token>
   ```

3. Restart the agent service (see [Pairing](#pairing-with-your-account)) and connect to the device from your browser.

## How it works

DirectGate has three pieces; only the agent lives in this repository:

- **Agent** (this repo) - runs on your machine: authenticates the client, spawns a PTY, serves the file manager, and encrypts all traffic end-to-end.
- **Relay / signaling** - operated by directgate.io. Pairs agents and clients, carries signaling, and forwards encrypted payloads when a direct link isn't possible. It never sees plaintext.
- **Client** - the web client at directgate.io, or the experimental `dgcli` in this repo.

After authentication, the client and agent negotiate a WebRTC peer-to-peer data channel. Once it opens, terminal I/O and file transfers flow **directly between the two peers**, bypassing the relay:

```
+--------------+              +-----------------+              +--------------+
|   DG agent   | <-- WSS -->  |  directgate.io  |  <-- WSS --> |    Client    |
|    (PTY)     |              |   (signaling)   |              | (web / CLI)  |
+--------------+              +-----------------+              +--------------+
       ^                                                              ^
       |               WebRTC Data Channel (direct P2P)               |
       +--------------------------------------------------------------+
          (DTLS transport + AES-256-SIV application-layer encryption)
```

If a direct path can't be established, the connection degrades gracefully - TURN, then the WebSocket relay - and stays end-to-end encrypted throughout. The client always shows which path is active.

See [Architecture](docs/architecture.md) and [WebRTC P2P & connectivity](docs/webrtc.md) for details.

## Security

The agent is the component that runs on your machine, so its cryptography is exactly what you can audit here.

- **TLS (WSS)** on every signaling connection
- **DTLS** on the WebRTC data channel
- **End-to-end encryption** with AES-256-SIV at the application layer - keys derived from the SRP session key via HKDF-SHA256, separate per direction, with per-packet nonces and a monotonic replay counter
- **SRP-6a** authentication - the password is never transmitted in any form
- **Optional Ed25519 key authorization** in addition to SRP

The relay can never read terminal, file, editor, or signaling payloads. It does necessarily see routing metadata - device ID, source IPs, connection timing, and traffic volume - which is inherent to any relay.

See [Security model](docs/security.md) for the full design and trust assumptions, and [directgate.io/security](https://directgate.io/security) for the threat model and FAQ.

## Installation

The easiest way to install the agent is from the official DirectGate package repositories. Once added, the agent stays up to date through your normal system updates. The debugsource packages are published for every release, so you can rebuild from source and compare against the distributed binaries.

Supported on Linux, Windows and macOS across x86, x86_64, ARMHF and ARM64 architectures.

**Debian / Ubuntu / Raspbian (apt)**

```bash
# Add the DirectGate signing key
curl -fsSL https://pkg.directgate.io/keys/directgate.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/directgate.gpg

# Add the DirectGate repository
echo "deb [signed-by=/usr/share/keyrings/directgate.gpg] https://pkg.directgate.io/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/directgate.list

# Install
sudo apt update
sudo apt install directgate
```

**Fedora / RHEL / Alma / Rocky (dnf)**

```bash
# Add the DirectGate signing key
sudo rpm --import https://pkg.directgate.io/keys/directgate.asc

# Add the DirectGate repository
sudo tee /etc/yum.repos.d/directgate.repo >/dev/null <<'EOF'
[directgate]
name=DirectGate
baseurl=https://pkg.directgate.io/rpm/el/8/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://pkg.directgate.io/keys/directgate.asc
EOF

# Install
sudo dnf install directgate
```

**macOS (Homebrew)**

```bash
brew tap directgate/directgate
brew install directgate
```

Windows installation instructions are coming soon.

**From source** - if your platform isn't listed above, or you want to build and audit the agent yourself, see [Building from source](docs/building.md). The short version:

```bash
git clone --recurse-submodules https://github.com/directgate/directgate.git
cd directgate-agent
cmake -B build && cmake --build build -j
sudo make -C build install
```

## Pairing with your account

After installing the agent, pair it with your directgate.io account so it shows up in your workspace:

1. Sign in at [directgate.io](https://directgate.io) and add a new device. The web client generates a ready-to-run pairing command - copy it and run it on the machine where the agent is installed:

   ```bash
   directgate -sed <device_id> -t <pairing_token>
   ```

   This initializes the SRP verifier (`-s`), enrolls the device (`-e`), sets the device ID (`-d`), and supplies the pairing token (`-t`). The agent contacts the API, enrolls, and stores its access/refresh tokens, routing key, relay URL, and any account-configured STUN/TURN servers in its config. Tokens and the ICE server list refresh automatically on subsequent runs.

2. Restart the agent service so it picks up the new configuration:

   ```bash
   sudo systemctl restart directgate-agent   # Linux (systemd)
   brew services restart directgate          # macOS (Homebrew)
   ```

The device now appears in your workspace and you can connect to it from the web client. You can re-run the pairing command at any time to re-pair, rotate the agent identity keypair with `directgate -r`, or change the SRP password with `directgate -s`.

See [Configuration & running](docs/configuration.md) for the full config reference and command-line options.

## Documentation

| Topic | Description |
|-------|-------------|
| [Architecture](docs/architecture.md) | How the agent, relay, and client fit together; transport diagrams; session multiplexing |
| [Security model](docs/security.md) | TLS, DTLS, AES-256-SIV E2E encryption, SRP-6a, key authorization, and trust assumptions |
| [WebRTC P2P & connectivity](docs/webrtc.md) | P2P negotiation, ICE/TURN configuration, and fallback tiers |
| [Protocol specification](docs/protocol.md) | Binary framing, message types, and header fields |
| [File transfer & file manager](docs/file-manager.md) | The `manager` and `file` protocols, chunked transfer, and integrity checks |
| [Configuration & running](docs/configuration.md) | Config file reference, CLI options, and systemd hardening |
| [Building from source](docs/building.md) | Requirements, build, install, tests, and repository layout |

## Why open source

DirectGate is built around a simple principle: software that runs on your machines should be auditable. The cloud infrastructure (API, relay, account management, web client) is operated by directgate.io, but the agent that runs on your computers and servers is fully open source. You can:

- Audit the source code
- Build the agent from source
- Compare releases against published source packages
- Independently reproduce binaries

## License

DirectGate is licensed under the GNU General Public License v3.0.

Copyright (C) 2025 – 2026 DirectGate (contact@directgate.io)

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the [LICENSE](LICENSE) file for the full license text.
