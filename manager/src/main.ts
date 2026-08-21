import { invoke } from "@tauri-apps/api/core";

/*
 * Thin wrappers around the Rust commands. The command names are snake_case
 * (Tauri's convention) while their JS-facing API mirrors the spec.
 *
 * Returned promises resolve with the command's success output and reject with
 * the error string produced by the Rust side (stderr / diagnostic message).
 */
function pairDevice(
  deviceId: string,
  pairingToken: string,
  authPassword: string,
): Promise<string> {
  return invoke<string>("pair_device", { deviceId, pairingToken, authPassword });
}

function getPairingStatus(): Promise<string> {
  return invoke<string>("get_pairing_status");
}

function getServiceStatus(): Promise<string> {
  return invoke<string>("get_service_status");
}

function startService(): Promise<string> {
  return invoke<string>("start_service");
}

function stopService(): Promise<string> {
  return invoke<string>("stop_service");
}

function restartService(): Promise<string> {
  return invoke<string>("restart_service");
}

function openUrl(url: string): Promise<void> {
  return invoke<void>("open_url", { url });
}

function changeSrpPassword(authPassword: string): Promise<string> {
  return invoke<string>("change_srp_password", { authPassword });
}

/*
 * Version / update state, as reported by the Rust side.
 *
 * `state` is the whole vocabulary of the footer:
 *   current     - the installed agent matches the published release
 *   outdated    - something newer is published; `url` is where to get it
 *   ahead       - installed is newer than published (a local or CI build)
 *   unknown     - the check could not complete; `detail` says why
 *   unsupported - a platform where a package manager owns the agent
 */
interface UpdateInfo {
  installed: string | null;
  latest: string | null;
  state: "current" | "outdated" | "ahead" | "unknown" | "unsupported";
  url: string | null;
  md5: string | null;
  supported: boolean;
  detail: string | null;
}

function getAgentVersion(): Promise<string> {
  return invoke<string>("get_agent_version");
}

function checkForUpdate(): Promise<UpdateInfo> {
  return invoke<UpdateInfo>("check_for_update");
}

const NOT_INSTALLED_MSG =
  "DirectGate service is not installed. Please install DirectGate Agent first.";

/*
 * Pairing code format (produced by directgate.io, consumed here)
 * -------------------------------------------------------------
 * A single copy-paste token that bundles the device ID and the one-time
 * pairing token, so the user copies one value instead of two:
 *
 *     dg1_<base64url( deviceId + "\n" + pairingToken )>
 *
 *   - "dg1_" is a version prefix (v1). It is accepted but optional on input.
 *   - The payload is base64url (RFC 4648 §5), padding optional.
 *   - deviceId and token are split on the FIRST newline, so the token may
 *     contain any character (':', '.', '/', etc.) without escaping.
 */
const PAIR_CODE_PREFIX = "dg1_";

interface PairParts {
  deviceId: string;
  token: string;
}

/** Decodes a `dg1_` pairing code into its device ID and pairing token. */
function decodePairCode(code: string): PairParts {
  let body = code.trim();
  if (body.startsWith(PAIR_CODE_PREFIX)) {
    body = body.slice(PAIR_CODE_PREFIX.length);
  }
  if (!body) throw new Error("Pairing code is empty.");

  // base64url -> base64, then restore any stripped '=' padding.
  let b64 = body.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";

  let text: string;
  try {
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    text = new TextDecoder().decode(bytes);
  } catch {
    throw new Error("Pairing code is not valid. Copy it again from directgate.io.");
  }

  const nl = text.indexOf("\n");
  if (nl < 0) {
    throw new Error("Pairing code is not valid. Copy it again from directgate.io.");
  }
  const deviceId = text.slice(0, nl).trim();
  const token = text.slice(nl + 1).trim();
  if (!deviceId || !token) {
    throw new Error("Pairing code is not valid. Copy it again from directgate.io.");
  }
  return { deviceId, token };
}

// --- element handles ---------------------------------------------------------
const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

const pairedView = $<HTMLDivElement>("paired-view");
const pairForm = $<HTMLDivElement>("pair-form");
const repairBtn = $<HTMLButtonElement>("repair-btn");
const workspaceLink = $<HTMLAnchorElement>("workspace-link");
const pairedWorkspaceLink = $<HTMLAnchorElement>("paired-workspace-link");
const pairCodeEl = $<HTMLInputElement>("pair-code");
const authEl = $<HTMLInputElement>("auth-password");
const confirmEl = $<HTMLInputElement>("confirm-password");
const pairBtn = $<HTMLButtonElement>("pair-btn");
const pairBackBtn = $<HTMLButtonElement>("pair-back-btn");
const pairMsg = $<HTMLParagraphElement>("pair-msg");

const changeSrpBtn = $<HTMLButtonElement>("change-srp-btn");
const srpForm = $<HTMLDivElement>("srp-form");
const srpPasswordEl = $<HTMLInputElement>("srp-password");
const srpConfirmEl = $<HTMLInputElement>("srp-confirm");
const srpSubmitBtn = $<HTMLButtonElement>("srp-submit-btn");
const srpCancelBtn = $<HTMLButtonElement>("srp-cancel-btn");

const verDot = $<HTMLSpanElement>("ver-dot");
const verInstalled = $<HTMLSpanElement>("ver-installed");
const verState = $<HTMLSpanElement>("ver-state");
const verDownload = $<HTMLAnchorElement>("ver-download");
const verCheckBtn = $<HTMLButtonElement>("ver-check-btn");

const statusValue = $<HTMLSpanElement>("status-value");
const actionBtn = $<HTMLButtonElement>("action-btn");
const stopBtn = $<HTMLButtonElement>("stop-btn");
const refreshBtn = $<HTMLButtonElement>("refresh-btn");
const serviceMsg = $<HTMLParagraphElement>("service-msg");

// Whether the action button currently starts or restarts the service.
let actionKind: "start" | "restart" = "start";

// --- helpers -----------------------------------------------------------------
type MsgKind = "ok" | "err" | "info";

function setMsg(el: HTMLElement, text: string, kind: MsgKind): void {
  el.textContent = text;
  el.className = `msg msg--${kind}`;
}

function clearMsg(el: HTMLElement): void {
  el.textContent = "";
  el.className = "msg";
}

function setStatusLabel(text: string, variant: string): void {
  statusValue.textContent = text;
  statusValue.className = `status__value status__value--${variant}`;
}

// --- pairing state -----------------------------------------------------------
// Collapses the "change SRP password" sub-form and clears its inputs.
function hideSrpForm(): void {
  srpForm.hidden = true;
  srpPasswordEl.value = "";
  srpConfirmEl.value = "";
}

function showPairedView(): void {
  pairedView.hidden = false;
  pairForm.hidden = true;
  // Nothing to go "back" to from the paired view; reset the form's Back button.
  pairBackBtn.hidden = true;
  hideSrpForm();
}

function showPairForm(): void {
  pairedView.hidden = true;
  pairForm.hidden = false;
  hideSrpForm();
}

async function refreshPairing(): Promise<void> {
  try {
    const status = await getPairingStatus();
    if (status === "Paired") {
      showPairedView();
    } else {
      showPairForm();
    }
  } catch {
    // If we can't tell, default to showing the form.
    showPairForm();
  }
}

// --- version / updates -------------------------------------------------------
/*
 * The footer has one job: answer "am I running the current version?" without
 * ever getting in the way of the two things the window is actually for. So it
 * only ever paints three elements - a dot, a version, and one short phrase -
 * and the phrase becomes a link exactly when there is somewhere to go.
 */
type VerTone = "idle" | "busy" | "ok" | "update" | "err";

/** Latest successful check, so the update link knows where to point. */
let updateUrl: string | null = null;

function paintVersion(
  tone: VerTone,
  version: string,
  state: string,
  detail?: string,
): void {
  verDot.className =
    tone === "idle" ? "appfoot__dot" : `appfoot__dot appfoot__dot--${tone}`;
  verInstalled.textContent = version;
  verState.textContent = state;
  // The reason a check failed belongs on hover, not in a 420px-wide line.
  verState.title = detail ?? "";
  verDownload.hidden = true;
}

function paintUpdateAvailable(info: UpdateInfo): void {
  verDot.className = "appfoot__dot appfoot__dot--update";
  verInstalled.textContent = info.installed ? `v${info.installed}` : "";
  // Left empty so the line carries one separator, not two: the link says
  // everything the state text would have.
  verState.textContent = "";
  verState.title = "";

  updateUrl = info.url;
  verDownload.textContent = `Update to ${info.latest}`;
  // Opens the update page, not the installer: upgrading stops the service and
  // drops whatever remote session the user is in, which is worth reading
  // before it happens rather than after a download has already started.
  verDownload.title = info.md5
    ? `Opens directgate.io/update\nInstaller MD5: ${info.md5}`
    : "Opens directgate.io/update";
  verDownload.hidden = false;
}

function applyUpdateInfo(info: UpdateInfo): void {
  const version = info.installed ? `v${info.installed}` : "";

  // Only offer the button where checking means anything; on Linux and macOS
  // the package manager owns the agent and this window has no business
  // second-guessing it.
  verCheckBtn.hidden = !info.supported;

  switch (info.state) {
    case "outdated":
      paintUpdateAvailable(info);
      break;
    case "current":
      paintVersion("ok", version, "Latest version");
      break;
    case "ahead":
      // A local or CI build, which is a fact worth stating plainly rather than
      // dressing up as either "current" or "out of date".
      paintVersion("idle", version, `Newer than the published ${info.latest}`);
      break;
    case "unsupported":
      paintVersion("idle", version, "");
      break;
    default:
      paintVersion(
        "err",
        version,
        "Update check unavailable",
        info.detail ?? undefined,
      );
      break;
  }
}

async function runUpdateCheck(): Promise<void> {
  verCheckBtn.disabled = true;
  verDot.className = "appfoot__dot appfoot__dot--busy";
  verState.textContent = "Checking\u2026";
  verState.title = "";
  verDownload.hidden = true;

  try {
    applyUpdateInfo(await checkForUpdate());
  } catch (err) {
    // check_for_update reports trouble in its result rather than by failing,
    // so reaching here means the command itself did not run.
    paintVersion("err", verInstalled.textContent ?? "", "Update check unavailable", String(err));
  } finally {
    verCheckBtn.disabled = false;
  }
}

/*
 * Two probes, in this order on purpose: the local one answers instantly and
 * fills the line, so the footer never starts as a blank strip waiting on the
 * network. The remote one then upgrades it in place.
 */
async function initVersionFooter(): Promise<void> {
  try {
    paintVersion("idle", `v${await getAgentVersion()}`, "");
  } catch {
    paintVersion("idle", "", "Agent not installed");
    // Nothing to compare against, so there is nothing to check either.
    return;
  }

  await runUpdateCheck();
}

// --- service status ----------------------------------------------------------
async function refreshStatus(): Promise<void> {
  refreshBtn.disabled = true;
  try {
    const status = await getServiceStatus();
    applyStatus(status);
  } catch (err) {
    // A failing status probe should never crash the UI.
    applyStatus("Unknown");
    setMsg(serviceMsg, String(err), "err");
  } finally {
    refreshBtn.disabled = false;
  }
}

function applyStatus(status: string): void {
  switch (status) {
    case "Running":
      setStatusLabel("Running", "running");
      actionKind = "restart";
      actionBtn.textContent = "Restart Service";
      actionBtn.disabled = false;
      stopBtn.disabled = false;
      clearMsg(serviceMsg);
      break;
    case "Stopped":
      setStatusLabel("Stopped", "stopped");
      actionKind = "start";
      actionBtn.textContent = "Start Service";
      actionBtn.disabled = false;
      stopBtn.disabled = true;
      clearMsg(serviceMsg);
      break;
    case "NotInstalled":
      setStatusLabel("Not installed", "notinstalled");
      actionKind = "start";
      actionBtn.textContent = "Start Service";
      actionBtn.disabled = true;
      stopBtn.disabled = true;
      setMsg(serviceMsg, NOT_INSTALLED_MSG, "info");
      break;
    default:
      setStatusLabel("Unknown", "unknown");
      actionKind = "start";
      actionBtn.textContent = "Start Service";
      actionBtn.disabled = false;
      stopBtn.disabled = false;
      clearMsg(serviceMsg);
      break;
  }
}

// --- actions -----------------------------------------------------------------
async function onPair(): Promise<void> {
  const authPassword = authEl.value;
  const confirmPassword = confirmEl.value;

  if (!pairCodeEl.value.trim()) {
    setMsg(pairMsg, "Pairing code is required.", "err");
    pairCodeEl.focus();
    return;
  }

  // Split the single pasted code back into device ID + pairing token.
  let deviceId: string;
  let token: string;
  try {
    ({ deviceId, token } = decodePairCode(pairCodeEl.value));
  } catch (err) {
    setMsg(pairMsg, String(err instanceof Error ? err.message : err), "err");
    pairCodeEl.focus();
    return;
  }

  if (!authPassword.trim()) {
    setMsg(pairMsg, "Auth password is required.", "err");
    authEl.focus();
    return;
  }
  if (authPassword !== confirmPassword) {
    setMsg(pairMsg, "Passwords do not match.", "err");
    confirmEl.focus();
    return;
  }

  pairBtn.disabled = true;
  setMsg(pairMsg, "Pairing…", "info");
  try {
    await pairDevice(deviceId, token, authPassword);
    // Pairing succeeded: switch to the paired view and restart the service so
    // it picks up the new enrollment.
    showPairedView();
    setMsg(pairMsg, "Device paired. Restarting service…", "info");
    try {
      const restarted = await restartService();
      setMsg(pairMsg, `Device paired. ${restarted}`, "ok");
    } catch (e) {
      setMsg(pairMsg, `Device paired, but service restart failed: ${e}`, "err");
    }
    await refreshStatus();
  } catch (err) {
    setMsg(pairMsg, String(err), "err");
  } finally {
    // Never keep the secrets around once the request is done. The pairing
    // code embeds the one-time token, so clear it too.
    pairCodeEl.value = "";
    authEl.value = "";
    confirmEl.value = "";
    pairBtn.disabled = false;
  }
}

// Changes the SRP auth password on the already-paired device.
async function onChangeSrp(): Promise<void> {
  const newPassword = srpPasswordEl.value;
  const confirmPassword = srpConfirmEl.value;

  if (!newPassword.trim()) {
    setMsg(pairMsg, "New auth password is required.", "err");
    srpPasswordEl.focus();
    return;
  }
  if (newPassword !== confirmPassword) {
    setMsg(pairMsg, "Passwords do not match.", "err");
    srpConfirmEl.focus();
    return;
  }

  srpSubmitBtn.disabled = true;
  setMsg(pairMsg, "Changing password…", "info");
  try {
    await changeSrpPassword(newPassword);
    // The agent loads the SRP verifier at startup, so restart the service for
    // the new password to take effect.
    setMsg(pairMsg, "Password changed. Restarting service…", "info");
    try {
      const restarted = await restartService();
      setMsg(pairMsg, `Password changed. ${restarted}`, "ok");
    } catch (e) {
      setMsg(pairMsg, `Password changed, but service restart failed: ${e}`, "err");
    }
    hideSrpForm();
    await refreshStatus();
  } catch (err) {
    setMsg(pairMsg, String(err), "err");
  } finally {
    // Never keep the new password around once the request is done.
    srpPasswordEl.value = "";
    srpConfirmEl.value = "";
    srpSubmitBtn.disabled = false;
  }
}

async function runServiceAction(
  action: () => Promise<string>,
  pending: string,
): Promise<void> {
  actionBtn.disabled = true;
  stopBtn.disabled = true;
  setMsg(serviceMsg, pending, "info");
  try {
    const out = await action();
    setMsg(serviceMsg, out, "ok");
  } catch (err) {
    setMsg(serviceMsg, String(err), "err");
  } finally {
    await refreshStatus();
  }
}

// --- wiring ------------------------------------------------------------------
pairBtn.addEventListener("click", onPair);

repairBtn.addEventListener("click", () => {
  showPairForm();
  // Re-Pair was reached from the paired view, so offer a way back to it.
  pairBackBtn.hidden = false;
  clearMsg(pairMsg);
  pairCodeEl.focus();
});

// Return from the (Re-Pair) form to the paired view without re-pairing.
pairBackBtn.addEventListener("click", () => {
  showPairedView();
  clearMsg(pairMsg);
});

// Toggle the "change SRP password" sub-form (acts as Cancel when already open).
changeSrpBtn.addEventListener("click", () => {
  if (srpForm.hidden) {
    srpForm.hidden = false;
    clearMsg(pairMsg);
    srpPasswordEl.focus();
  } else {
    hideSrpForm();
  }
});

srpSubmitBtn.addEventListener("click", onChangeSrp);

// Collapse the SRP sub-form and return to the plain paired view.
srpCancelBtn.addEventListener("click", () => {
  hideSrpForm();
  clearMsg(pairMsg);
});

srpConfirmEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") onChangeSrp();
});

// Open external links in the system browser instead of letting the webview
// navigate away from the manager UI.
function wireExternalLink(link: HTMLAnchorElement): void {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    openUrl(link.href).catch((err) => {
      setMsg(pairMsg, `Could not open the browser: ${err}`, "err");
    });
  });
}

wireExternalLink(workspaceLink);
wireExternalLink(pairedWorkspaceLink);

verCheckBtn.addEventListener("click", runUpdateCheck);

// The update link points at whatever the last check resolved, falling back to
// the update page baked into the markup.
verDownload.addEventListener("click", (e) => {
  e.preventDefault();
  openUrl(updateUrl ?? verDownload.href).catch((err) => {
    verState.textContent = "Could not open the browser";
    verState.title = String(err);
  });
});

refreshBtn.addEventListener("click", refreshStatus);

actionBtn.addEventListener("click", () => {
  if (actionKind === "restart") {
    runServiceAction(restartService, "Restarting service…");
  } else {
    runServiceAction(startService, "Starting service…");
  }
});

stopBtn.addEventListener("click", () =>
  runServiceAction(stopService, "Stopping service…"),
);

confirmEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") onPair();
});

// Initial probes.
refreshPairing();
refreshStatus();
initVersionFooter();
