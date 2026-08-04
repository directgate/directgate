[Back to README](../README.md)

# Linux desktop sessions

The agent streams an Xorg desktop with XShm capture and XTest input, and a Wayland desktop through `xdg-desktop-portal` + PipeWire. Which one is used is decided from the session type, not from what happens to be installed.

## Xorg

Nothing is required beyond the X11 libraries the agent already links. Capture uses MIT-SHM where available and falls back to `XGetImage`; input goes through the XTest extension, which is loaded at runtime.

## Building with Wayland support

Wayland streaming is compiled in only when the PipeWire and D-Bus **headers** are present at configure time. Neither library is linked - both are loaded at runtime - so these are build-time dependencies only, and their absence costs nothing on an X11-only host:

```sh
sudo dnf install pipewire-devel dbus-devel         # Fedora / RHEL
sudo apt install libpipewire-0.3-dev libdbus-1-dev # Debian / Ubuntu
sudo pacman -S libpipewire dbus                    # Arch
```

Configure prints which one it took:

```
-- Wayland desktop streaming: enabled (PipeWire 1.4.11 headers, runtime dlopen)
```

If it says `disabled`, the agent reports *"This agent was built without Wayland desktop streaming"* at run time. Install the packages and **re-run cmake** - a plain `cmake --build` will not re-check. If configure still says disabled afterwards, delete `CMakeCache.txt` and configure again.

## Wayland sessions

The agent streams a Wayland desktop through `xdg-desktop-portal`: the compositor is asked for permission, the pixels then arrive over PipeWire, and keyboard and pointer events go back through the portal's RemoteDesktop interface. A Wayland client cannot read the screen or synthesise input on its own, and DirectGate does not try to work around that.

Requirements on the streamed machine:

- `pipewire` and `dbus` runtime libraries (both already present on a normal desktop install). They are loaded at runtime, not linked, so an X11-only host without them runs the same binary unchanged.
- A desktop portal with a ScreenCast **and** RemoteDesktop backend - `xdg-desktop-portal-gnome` or `xdg-desktop-portal-kde`. A wlroots-only setup (`xdg-desktop-portal-wlr`) can capture but cannot inject input.

The first connection raises a permission prompt on the remote machine, which someone has to be there to allow. Until they do, the session waits with *"Waiting for screen sharing to be allowed on the remote computer"* rather than streaming a black screen. Once allowed, the grant is remembered in `~/.config/directgate/wayland.token` (owner-only) and later connections start without a prompt.

A remembered grant covers the screens it was granted for, so it stops working when those screens change - closing a laptop lid is enough, and the portal then restores the session with **no stream at all** rather than with the monitors that are still there. The agent treats that as a grant that has expired: the token is deleted and the prompt goes back up once, for the screens that exist now. Answering "no" is different and is taken as an answer - a refusal never summons a second prompt.

Persistence is asked for on `RemoteDesktop.SelectDevices`, because on a session that owns input it is the **device** grant being remembered and its token is a RemoteDesktop token. `ScreenCast.SelectSources` is not offered that token: restoring is not its to do, and every option sent is one a portal can refuse - a refusal fails the whole request, not just the option.

Asking to be remembered and presenting a remembered grant are also **separate** steps, and only the second is given up when the portal refuses it. A token the portal will not take therefore costs one prompt, after which a new one is stored. (Dropping both together is how an agent ends up prompting on every single connection and never storing anything - fatal for a machine nobody is sitting at.)

The log says which happened:

```
Desktop portal accepted the input options: options(types+persist+restore)   <- resumed silently
Desktop portal accepted the input options: options(types+persist)           <- prompted once, will store a new grant
Desktop sharing permission remembered: restore(yes)                         <- a token came back
Wayland sharing permission stored; the next connection should not prompt
```

One behaviour differs from X11 and is the compositor's rule, not a choice this agent makes:

- **The monitor list is the grant, not the hardware.** The portal offers only the screens the person picked, so a second monitor appears in the list once it has been shared and not before.

The cursor works the way it does everywhere else. The host pointer is kept out of the video (`cursor_mode: hidden`), so the viewer sees one cursor - their own - and it is over whatever it is pointing at. Under **mouse capture** the browser hides its own pointer and draws the host cursor instead, from the position the agent echoes back after every relative movement. Because the portal accelerates relative motion but not absolute motion, the agent integrates those movements itself and replays them as absolute portal motion: the drawn cursor and the real pointer then move by exactly the same amount, which is what makes a click land where the cursor is.

**Caps Lock and Num Lock travel as ordinary keys** here, where the Xorg path instead syncs the lock *state* and keeps the keys to itself. The portal can press a key but can neither read nor set a lock, so a Wayland agent reports `lockSync: false` and the browser forwards the lock keys - which is what toggles the lock on that host. Claiming the sync it cannot do was worse than not offering it: the browser swallowed the keys, the state it sent instead went nowhere, and a host that had ended up in Caps Lock typed in capitals with nothing the viewer could press to get out of it.

Keys are released, not just injected. Every key the browser presses is tracked by its physical code and released by that code, so a press reported as `A` and a release reported as `a` still let go of the same key; whatever is still down when the session ends is released before the portal session closes; and a key that stays down through 30 seconds of complete silence is taken to have lost its release and let go. Without that last part a Shift whose keyup never arrived - a browser shortcut swallows it, a transport change drops it - stays down in the portal's virtual keyboard for as long as the agent runs, and the entire machine types in capitals.

Nothing else about the X11 path changes. The session type is decided before the display is opened, because XWayland sets `DISPLAY` on a Wayland session too and capturing that would silently produce a black screen: a machine that reports `XDG_SESSION_TYPE=x11` is always treated as X11.

The permission prompt is answered by a person, so the session waits for them rather than failing. A start that finds the prompt unanswered reports `starting` with that message and keeps the timer running; the moment the grant lands the agent reports `ready` and the viewer picks a screen. Nothing has to be reconnected - which is what used to be required, because a start that gave up left nothing behind to look again.

## Keyboard layout

Both backends decide **per keystroke** whether the viewer's keyboard layout or the host's decides what gets typed, because neither answer is right on its own. The browser reports what a key *is* (its physical position) and what it *produced* (after the viewer's own layout):

- The character is exactly what that position types on a plain US layout, or the key types nothing at all (Enter, F5, Shift, arrows): the **position** is sent and the **host's layout decides**. A host whose keyboard is set to Georgian types Georgian, exactly as it would for someone sitting at it - including its own layout-switching shortcut, which arrives as the same physical combination.
- The character is anything else: the **character** is sent and the **viewer's layout decides**. This covers every non-Latin keyboard - a Georgian keyboard reports `ა` where the position holds `a` - and equally the Latin layouts that move keys around, so a German `z` is typed as `z` and not as the `y` sitting in that position.

Sending only characters (which is what this agent used to do) cannot type a script the host layout does not contain: on Wayland the compositor has no key to put a Georgian letter on when its keyboard is English, and asking for one silently types nothing. Sending only positions would make a Georgian keyboard type Latin. The split is what makes both work.
