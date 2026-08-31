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

Nothing here talks to a compositor directly, so the backend is interchangeable in principle - but backends differ in what they implement, and three differences are worth knowing about. Each says so in the log rather than failing quietly:

| What differs | If the backend does not do it | Log line |
|---|---|---|
| Typing **by character** (`NotifyKeyboardKeysym`) | Keys the host layout carries still work (those go in by position); characters from another layout do not type at all. The viewer is told once. | `The desktop portal refused an input event: method(NotifyKeyboardKeysym...)` |
| Remembering the grant (`persist_mode` on RemoteDesktop) | Works, but every connection has to be allowed on the remote computer. | `Desktop sharing permission remembered: restore(no)` |
| Honouring the buffer-type constraint | The compositor hands back DMA-BUFs this agent cannot map, and the stream is black. | `received a buffer it cannot map` |

GNOME (Mutter) does all three; that is where this has been run.

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

**The encoder is the same one Xorg uses.** A Wayland session is a different *source* of frames, not a second pipeline: the portal's PipeWire stream replaces the XShm capture, and everything after it - the scale to the encode size, the colour conversion, the GPU encoder probe (`h264_nvenc` -> `h264_vaapi` -> `h264_qsv` -> `h264_amf` -> `h264_v4l2m2m`), the adaptive bitrate controller, the frame mailbox - is the code in `desktop_linux.c` that Xorg runs. Hardware encoding is therefore neither enabled nor disabled by the session type, and the pipeline start line names the backend the frames actually came from:

```
Wayland H.264 pipeline started: sid(3), capture(0,0 2560x1440), encode(1920x1080), shm(n/a), encoder(hardware: h264_vaapi, zero-copy DMA-BUF), preset(balanced)
```

What does differ is *when* a frame reaches that encoder. Xorg is pulled - being due and capturing are the same instant, so what is encoded is the screen as it is right now - while PipeWire pushes on the compositor's clock and sends nothing at all while the screen is still. A tick that finds nothing has therefore not proved the desktop is idle, so the capture thread waits for the frame (for at most one frame period, which the tick has already spent) instead of going back to sleep and letting a change that landed a millisecond too late sit there until the next one. That is worth up to a whole frame period on exactly the case a remote desktop is judged on: the first frame after a still moment, which is what a keystroke produces. The frame itself is then handed to the encoder rather than copied into it.

**Zero-copy: the frame need not come back to the CPU at all.** When the encoder that would be used is VAAPI, the agent offers the compositor a second way to hand frames over - as DMA-BUF, the GPU buffer itself rather than a readback of it. What arrives is then a handle, not pixels: it is mapped into a VAAPI surface (`av_hwframe_map`), the driver's video post-processor does the colour conversion *and* the resize to the encode size (`scale_vaapi`), and the encoder is opened on the post-processor's own output pool so the surface it writes is the surface the encoder reads. Nothing between the screen and the H.264 bitstream is read, converted or copied by this process. On a 4K screen that removes a GPU readback, two full-frame copies, a scalar BGRA-to-NV12 pass and an upload, per frame.

It is an offer, and every part of it can decline:

- **The encoder.** Only VAAPI can be handed a DRM object through libavcodec, so a host whose encoder is NVENC keeps the copied path. `libavfilter` is dlopen'd for the post-processor exactly like libavcodec and is optional at build time; without it, or without a `scale_vaapi` filter in the installed FFmpeg, or without any VAAPI device, the offer is never made.
- **The compositor.** The agent offers only the `INVALID` (driver's own) and `LINEAR` buffer layouts, because naming the tiled ones a GPU supports would mean linking an EGL stack into the agent. A compositor that will only produce something else simply negotiates the memory format instead, which is offered alongside.
- **The GPU, at the first frame.** An import the driver refuses cannot be discovered by asking, only by trying. The stream is then renegotiated for mapped memory in place and the encoder is rebuilt around it - the portal grant is untouched, so nobody is prompted and the session carries on with a keyframe.

`DIRECTGATE_HWENC_ZEROCOPY=0` turns the offer off. The pipeline start line says which way it went: `encoder(hardware: h264_vaapi, zero-copy DMA-BUF)` against `encoder(hardware: h264_vaapi (VA-API H.264 encoder))`, and the capture line says `frames(exported by the GPU)` or `frames(mapped memory)`.

One behaviour differs from X11 and is the compositor's rule, not a choice this agent makes:

- **The monitor list is the grant, not the hardware.** The portal offers only the screens the person picked, so a second monitor appears in the list once it has been shared and not before.

Two failures are reported rather than survived, because surviving them means showing something that is not the desktop:

- **Sharing stopped on the remote computer.** Pressing "Stop sharing", revoking the grant, or restarting the compositor ends the stream, and the only symptom is that frames stop arriving. The session notices and says so instead of leaving the viewer on the last frame, which is indistinguishable from a dead network.
- **No fallback to raw RGBA.** The raw path reads from an X display a Wayland session does not have, so falling back to it produces no frames at all while the session reports "streaming". A Wayland session that cannot encode reports the encoder's own reason and stops. `DIRECTGATE_DESKTOP_FORCE_RAW` is refused there for the same reason.

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
