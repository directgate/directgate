[Back to README](../README.md)

# Configuration & running

The agent uses a JSON configuration file. You can point to one with `-c <path>`, or create/update it interactively with `-i`. Most fields are populated for you during [pairing](../README.md#pairing-with-your-account) and interactive setup (`directgate -i`, `directgate -s`).

## Default configuration path

- Agent: `~/.config/directgate/agent.json` (falls back to `./agent.json` if `$HOME` is unset)

## Logging

```json
{
  "log": {
    "path": "/var/log/directgate",
    "toScreen": true,
    "toFile": false,
    "flush": true,
    "levels": ["panic", "error", "warn", "note", "info", "debug"]
  }
}
```

| Field          | Type    | Description              |
|----------------|---------|--------------------------|
| `log.toScreen` | boolean | Output logs to console   |
| `log.toFile`   | boolean | Write logs to file       |
| `log.path`     | string  | Log file directory       |

## Agent configuration

```json
{
  "signalingUrl": "wss://relay1.directgate.io/websock",
  "deviceId": "<unique_uuidv4>",
  "iceServers": [
    "stun:stun.cloudflare.com:3478",
    "stun:stun.l.google.com:19302"
  ],
  "shell": {
    "user": "username",
    "home": "/home/username"
  },
  "desktop": {
    "elevatedInput": true,
    "lockScreen": true
  },
  "auth": {
    "srp": {
      "verifier": "<srp_verifier_hex>",
      "salt": "<64_hex_chars>"
    },
    "key": {
      "agentIdentity": {
        "seed": "<base64_ed25519_seed>",
        "pub": "<base64_ed25519_public_key>"
      },
      "authorizedKeys": [
        "<base64_ed25519_client_public_key>"
      ]
    }
  }
}
```

| Field                         | Type     | Description                                |
|-------------------------------|----------|--------------------------------------------|
| `signalingUrl`                | string   | WebSocket relay endpoint URL               |
| `deviceId`                    | string   | Unique device identifier for pairing       |
| `iceServers`                  | string[] | Manual ICE/TURN override (optional; normally delivered by the API - see [WebRTC P2P](webrtc.md#iceturn-server-configuration)) |
| `shell.user`                  | string   | Unix user for the shell session            |
| `shell.home`                  | string   | Working directory for the shell            |
| `desktop.elevatedInput`       | bool     | **Windows only**, default `true`. Lets a desktop session drive privileged UI - UAC prompts, Task Manager, elevated windows - through the service's SYSTEM helper. Setting it to `false` leaves those visible but frozen. Read [Elevated UI and the secure desktop](windows.md#elevated-ui-and-the-secure-desktop) before changing it: with it on, a remote operator who approves a UAC prompt is effectively an administrator on the host |
| `desktop.lockScreen`          | bool     | **Windows only**, default `true`. Also allows the lock screen and the Ctrl+Alt+Del security screen. Ignored when `desktop.elevatedInput` is `false` |
| `auth.srp.salt`               | string   | SRP salt in hex (32 bytes / 64 hex chars)  |
| `auth.srp.verifier`           | string   | SRP verifier in hex                        |
| `auth.srp.suite`              | number   | SRP credential suite advertised at auth (managed by the agent; older records are upgraded in place on load) |
| `auth.key.agentIdentity.seed` | string   | Agent Ed25519 identity seed for key auth   |
| `auth.key.agentIdentity.pub`  | string   | Agent Ed25519 public identity for key auth |
| `auth.key.authorizedKeys`     | string[] | Authorized client Ed25519 public keys      |

## Running the agent

Run the installed binary directly:

```bash
directgate -c ~/.config/directgate/agent.json
```

If built from source without installing, the binary is at `build/directgate`.

### Command-line options

```
Usage: directgate [options]
Options are:
  -d <id>       Device ID for this agent
  -u <url>      WebSocket relay URL
  -c <path>     Config JSON path
  -l <path>     Log directory path
  -t <token>    Pairing token for enrollment
  -v <number>   Set/override verbosity level (0-5)
  -g <path>     Generate a client key file and exit
  -a <path>     Authorize this agent against an existing key file and exit
  -r            Rotate agent identity keypair, push new pub to API, and exit
  -w            Enable WebRTC verbose logging (works with -v)
  -i            Init config and exit
  -e            Enroll device and exit
  -s            Init SRP verifier and exit
  -h            Print version and usage
```

Common one-shot commands:

```bash
directgate -sed <id> -t <token>  # pair this device with your account and init config
directgate -i                    # create/update the agent config interactively
directgate -s                    # set/change the SRP password (regenerates the verifier)
directgate -r                    # rotate the agent identity keypair
```

## Systemd hardening

By default, DirectGate installs its systemd service with `PrivateTmp=true`, which gives the service isolated `/tmp` and `/var/tmp` directories. It also uses `NoNewPrivileges=false`, which is basically required to make `sudo` work correctly within remote terminal sessions (similar to how SSH works).

This default is a deliberate tradeoff between functionality and isolation. Although `NoNewPrivileges` is disabled, the agent does not execute user sessions with elevated privileges by default and drops privileges to the configured account before handling interactive workloads.

If you do not require `sudo` capabilities from remote sessions, you may set:

```ini
NoNewPrivileges=true
```

for additional hardening.

Administrators are also encouraged to apply further systemd sandboxing restrictions where appropriate, such as filesystem restrictions, capability filtering, address family restrictions, and other hardening directives based on their deployment requirements.

As with any remote access software, the appropriate hardening profile depends on the balance between functionality and security required by your environment.

## Experimental CLI client

The experimental `dgcli` client reads a minimal config:

```json
{
  "signalingUrl": "wss://relay1.directgate.io/websock",
  "deviceId": "<agent_unique_uuidv4>",
  "iceServers": ["stun:stun.cloudflare.com:3478"]
}
```

| Field          | Type     | Description                                |
|----------------|----------|--------------------------------------------|
| `signalingUrl` | string   | WebSocket relay endpoint URL               |
| `deviceId`     | string   | Agent ID to connect to                     |
| `iceServers`   | string[] | ICE/TURN server URLs for WebRTC (optional) |

The client password is entered interactively at runtime and is never stored in the client config.
