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

The default log directory is platform-specific: `/var/log/directgate` on Linux and macOS, and `%ProgramData%\directgate` (normally `C:\ProgramData\directgate`) on Windows, next to the machine-wide `agent.json`. Setting `log.path` overrides it everywhere; on Windows either separator may be used.

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

## CLI client

`dgcli` signs in to your DirectGate account, lists the devices on it and connects
to the one you pick - the same path the workspace UI takes.

### Signing in

```sh
dgcli login
```

This runs an OAuth 2.0 authorization code flow with PKCE. The CLI opens a short-lived listener on `127.0.0.1` (ports 40777-40784), opens your browser, and exchanges the returned authorization code for a session. Tokens are written
to `~/.config/directgate/auth/auth.json` with `0600` permissions inside a `0700` directory, created on demand alongside the client key, and refreshed automatically as they expire - you only sign in again when the refresh token is gone.

The CLI holds no identity-provider configuration of its own. It knows exactly two hosts - the API and the web app - and the code exchange and refresh go through `POST /api/v1/auth/cli/token` and `/api/v1/auth/cli/refresh`, which the
API performs against the provider on its behalf. Swapping the provider therefore needs no new CLI release, and the repository carries no provider credentials.

The link it prints points at `https://directgate.io/cli-auth/start`, which forwards to the auth provider. The web app never shows this URL - `supabase-js` navigates to it from JavaScript - but the CLI has to print it, so it goes through our own domain rather than asking you to trust a raw project host. The page takes only a loopback port and a mode; it rebuilds the redirect target itself, so the link cannot be rewritten to send an authorization code elsewhere. Set `webUrl` to empty at build time and the CLI falls back to printing the provider URL directly.

On a machine with no browser (a box you reached over SSH, for example) the CLI detects the missing display - or you pass `-B` - and asks for the code to come back through `https://directgate.io/cli-auth` instead. That page hands the code to the listener when it can reach it and otherwise shows it for you to paste back into the terminal.

`dgcli logout` deletes the stored session; `dgcli whoami` prints the account it belongs to.

### Connecting

```sh
dgcli                # pick a device with the arrow keys, then connect
dgcli homelab        # connect by device name, exact or unique prefix
dgcli -d <device-id> # connect by device id
dgcli devices        # just list the account's devices
```

The picker marks each device online (green), offline (yellow) or unavailable (red) and refuses to connect to devices the backend would reject anyway - unpaired, expired enrollment, or a share invitation you have not accepted. When stdin is not a terminal it falls back to a numbered prompt.

Once a device is chosen the CLI calls `POST /api/v1/sessions/connect`, which returns the relay URL, the short-lived browser JWT, the routing key and the ICE servers in one round trip. The routing key becomes the `?rk=` query parameter on the relay WebSocket handshake; without it the relay has no route to the agent and drops the connection.

The device password is prompted for after the device is chosen and is never written to disk.

### Key authentication

`dgcli` can authenticate with an Ed25519 key instead of typing the device password every time. The key is always tried first; the password is only reached when there is no usable key or the host refuses the one offered.

```sh
dgcli -g                 # generate a key at ~/.config/directgate/auth/key.json
dgcli -k /path/to/key.json <device>
```

`-g` writes the key `0600` inside a `0700` directory and prints the public half. `-A` then hands that public half to a device over an authenticated session - the same `admin/add-key` the workspace UI uses - so a device can be authorized from anywhere the CLI already reaches it:

```sh
dgcli -A                 # pick a device, authorize the key, exit
dgcli -A -d homelab      # or name the device
dgcli -A -k /path/to/other-key.json
```

Without `-d` it shows the usual device picker, headed with what it is about to do so the operator can see this is not a connection attempt. The key it adds is the one `-k` names, or the default path; with neither present it prints where the key would live and how to get one.

Since a key file holds a single identity, the key being authorized is by definition not yet authorized, so `-A` authenticates with the device password the way `ssh-copy-id` does. After that the password is no longer needed for that device.

A device can also authorize a key locally, without the CLI:

```sh
directgate -a /path/to/key.json
```

Without `-k`, `~/.config/directgate/auth/key.json` is used when it exists; `-k` always wins over it. The distinction matters on failure: an unusable `-k` is an error, because the key was asked for by name, while the default path simply not existing is the ordinary password-only setup.

Two things have to line up for a key attempt to happen. The key file has to load, and the device has to have published an `agentPub` during enrollment - that value comes from the API over TLS and is what the host is pinned to. A
host presenting any other identity is refused outright rather than falling back, since it is not provably the device that was asked for. A host that proves its identity but has not authorized the key is a different case: that is what the password is for, so the CLI reconnects and runs SRP instead.

The file is the same `directgate-client-key-v2` identity the agent generates and the web client loads, so one key works across all three.

### Client config

`dgcli` runs with no config at all. A `client.json` is only needed to override the built-in endpoints:

```json
{
  "apiUrl": "https://api.directgate.io",
  "webUrl": "https://directgate.io",
  "signalingUrl": "wss://relay1.directgate.io/websock",
  "iceServers": ["stun:stun.cloudflare.com:3478"]
}
```

| Field          | Type     | Description                                              |
|----------------|----------|----------------------------------------------------------|
| `apiUrl`       | string   | Control-plane API origin                                  |
| `webUrl`       | string   | Web app origin, hosts the `/cli-auth` sign-in page        |
| `signalingUrl` | string   | Relay endpoint; normally supplied by the session envelope |
| `apiToken`     | string   | Pre-issued bearer token; replaces the browser sign-in     |
| `keyPath`      | string   | Client key file tried before the password                 |
| `iceServers`   | string[] | ICE/TURN server URLs for WebRTC (optional)                |

`apiUrl` and `webUrl` may also be set per shell through `DIRECTGATE_API_URL` and `DIRECTGATE_WEB_URL`, which take precedence over the config file. Their compiled-in defaults come from the CMake cache variables of the same names, so a self-hosted build ships a binary that points at its own stack - and since those are the only endpoints it carries, that is all a fork has to change.

Setting `apiToken` skips the account sign-in entirely and is the path to use for automation, where no browser is available to authorize anything.
