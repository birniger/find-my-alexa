const app = document.querySelector("#app");
let activeSetupPoll = "";
let authClient = null;
let accessToken = "";
let config = null;

const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (character) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  "'": "&#39;",
  '"': "&quot;",
})[character] ?? character);

async function loadConfig() {
  const response = await fetch("/api/config");
  config = await response.json();
}

async function configureAuth() {
  if (!config.auth0Domain || !config.auth0ClientId) return;
  authClient = await window.auth0.createAuth0Client({
    domain: config.auth0Domain,
    clientId: config.auth0ClientId,
    authorizationParams: {
      audience: config.auth0Audience,
      redirect_uri: window.location.origin,
      scope: "openid profile email",
    },
    cacheLocation: "localstorage",
  });
  if (window.location.search.includes("code=") && window.location.search.includes("state=")) {
    await authClient.handleRedirectCallback();
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  if (await authClient.isAuthenticated()) accessToken = await authClient.getTokenSilently();
}

async function api(path, init = {}) {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(init.headers ?? {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "Request failed.");
  return payload;
}

function base64UrlToBytes(value) {
  const normalized = String(value || "").trim();
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const base64 = `${normalized}${padding}`.replaceAll("-", "+").replaceAll("_", "/");
  const raw = atob(base64);
  const bytes = Uint8Array.from([...raw].map((character) => character.charCodeAt(0)));
  if (bytes.length !== 65 || bytes[0] !== 4) throw new Error("Push notification configuration is invalid.");
  // WebKit rejects an ArrayBuffer application server key with a bare SyntaxError.
  return bytes;
}

function renderSignedOut() {
  app.innerHTML = `
    <header class="topbar">
      <a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a>
      <span class="beta-pill">Private beta</span>
    </header>
    <section class="hero">
      <div>
        <p class="eyebrow">Private beta</p>
        <h1>Ring your own Apple devices with Alexa.</h1>
        <p class="lede">Set up your Apple devices once, save this web app, and get renewal alerts before Alexa goes quiet.</p>
      </div>
      <button id="signIn" class="primary" type="button">Sign in</button>
    </section>
    <section class="status-grid">
      <article><span>Account</span><strong>Separate login</strong><small>Create a Device Finder username and password; Soundbox credentials stay separate.</small></article>
      <article><span>Alerts</span><strong>Push first</strong><small>${config.emailFallbackAvailable ? "Email follows only when push cannot reach you." : "Email fallback can be added after a sending domain is connected."}</small></article>
      <article><span>Access</span><strong>Invite only</strong><small>Each invited tester connects only their own Apple account and devices.</small></article>
    </section>
  `;
  document.querySelector("#signIn")?.addEventListener("click", () => void authClient.loginWithRedirect({
    authorizationParams: {
      connection: config.auth0Connection,
      prompt: "login",
    },
  }));
}

function renderAuthNotConfigured() {
  app.innerHTML = `
    <header class="topbar">
      <a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a>
      <span class="beta-pill">Local preview</span>
    </header>
    <section class="config-layout">
      <div class="panel main-panel config-copy">
        <p class="eyebrow">Setup needed</p>
        <h1>The private beta shell is installed.</h1>
        <p class="lede">Auth0 and Cloudflare resources still need production values before friends can sign in.</p>
      </div>
      <aside class="panel readiness-panel" aria-label="Production readiness">
        <div class="phone-visual" aria-hidden="true">
          <span></span><i></i><b></b>
        </div>
        <div class="readiness-list">
          <div><span>Auth0</span><strong>Missing production values</strong></div>
          <div><span>Cloudflare</span><strong>Worker shell ready</strong></div>
          <div><span>Setup relay</span><strong>Waiting for secrets</strong></div>
        </div>
      </aside>
    </section>
  `;
}

function renderDashboard(status) {
  const devices = status.devices ?? [];
  const readyDevices = devices.filter((device) => device.status === "ready");
  const device = devices[0] ?? null;
  const alexaState = status.alexa?.status ?? "unlinked";
  const unhealthy = devices.find((candidate) => candidate.last_health_status && candidate.last_health_status !== "healthy");
  const healthDevice = unhealthy || device;
  const ready = readyDevices.length > 0;
  const needsRenewal = devices.some((candidate) => candidate.status === "needs_renewal" || candidate.status === "unhealthy");
  const routineDevices = readyDevices.length ? readyDevices : devices.filter((candidate) => candidate.label);
  app.innerHTML = `
    <header class="topbar">
      <a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a>
      <nav>
        <button id="signOut" class="secondary" type="button">Sign out</button>
      </nav>
    </header>
    <section class="workspace">
      <div class="panel main-panel">
        <p class="eyebrow">${escapeHtml(status.account.displayName || status.account.email)}</p>
        <h1>${ready ? `${readyDevices.length} Apple ${readyDevices.length === 1 ? "device is" : "devices are"} ready.` : needsRenewal ? "Renew your Apple login." : "Set up your Apple devices."}</h1>
        <p class="lede">${ready ? "Alexa can ring the default device or a device you name." : "A live Apple setup session is needed before ringing works."}</p>
        <div class="actions">
          ${ready ? `<button id="addSavedDevice" class="primary" type="button">Add a device</button>` : ""}
          <button id="startSetup" class="${ready ? "secondary" : "primary"}" type="button">${ready ? "Sign in to Apple again" : "Set up devices"}</button>
        </div>
        ${ready ? `<p class="lede subtle">Adding a device reuses your saved Apple session, so there is no sign-in and no verification code.</p>` : ""}
        <p id="dashboardStatus" class="form-status"></p>
      </div>
      <section class="notification-setup" aria-labelledby="notificationHeading">
        <div><p class="eyebrow">Renewal alerts</p><h2 id="notificationHeading">Keep Alexa connected.</h2><p>Enable notifications on this device so Device Finder can tell you when Apple asks for a fresh login.</p></div>
        <div class="notification-action"><button id="enablePush" class="primary" type="button">Enable notifications</button><small id="pushStatus">On iPhone, open the saved Home Screen app first.</small></div>
      </section>
      <div class="status-grid compact">
        <article><span>Apple devices</span><strong>${escapeHtml(devices.length)}</strong><small>${escapeHtml(readyDevices.length)} ready</small></article>
        <article><span>Alexa</span><strong>${escapeHtml(alexaState.replaceAll("_", " "))}</strong><small>Account linking will connect your Echo.</small></article>
        <article><span>Health</span><strong>${escapeHtml(healthDevice?.last_health_status || "unknown")}</strong><small>${escapeHtml(devices.length > 1 && unhealthy ? `${unhealthy.label || "One device"} needs attention` : healthDevice?.last_checked_at || "No check yet")}</small></article>
      </div>
      <section class="panel">
        <header class="section-header"><h2>Your Apple devices</h2></header>
        <div class="device-list">
          ${devices.length ? devices.map((candidate, index) => `
            <article class="device-row">
              <div>
                <span>${index === 0 ? "Default · Alexa name" : "Alexa name"}</span>
                <strong>${escapeHtml(candidate.label || "Unnamed Apple device")}</strong>
                <small>${escapeHtml(candidate.model || candidate.status.replaceAll("_", " "))}</small>
                <form class="device-rename" data-rename-form="${escapeHtml(candidate.id)}" hidden>
                  <input name="label" value="${escapeHtml(candidate.label || "")}" maxlength="80" aria-label="Alexa name">
                  <button class="primary" type="submit">Save</button>
                  <button class="secondary" type="button" data-cancel-rename="${escapeHtml(candidate.id)}">Cancel</button>
                </form>
                <small class="rename-status" role="status" data-device-status="${escapeHtml(candidate.id)}"></small>
              </div>
              <div class="device-actions">
                <button class="secondary" type="button" data-rename-device="${escapeHtml(candidate.id)}">Rename</button>
                <button class="secondary" type="button" data-ring-device="${escapeHtml(candidate.id)}" ${candidate.status === "ready" ? "" : "disabled"}>Ring</button>
              </div>
            </article>
          `).join("") : `<p class="empty">No Apple devices set up yet.</p>`}
        </div>
      </section>
      <section class="panel alexa-guide">
        <header class="section-header"><h2>Alexa routines</h2></header>
        <p class="no-routine-note"><strong>Without a routine:</strong> say <code>Alexa, ask Device Finder to ring [Alexa name]</code>, or <code>Alexa, open Device Finder</code> to ring ${routineDevices.length > 1 ? "your default device" : "it"}.</p>
        <div class="routine-list">
          ${routineDevices.length ? routineDevices.map((candidate, index) => {
            const label = candidate.label || `Apple device ${index + 1}`;
            const when = `where is ${label}`;
            const action = `ask Device Finder to ring ${label}`;
            return `<article class="routine-block"><header><strong>${escapeHtml(label)}</strong>${index === 0 ? "<span>Default</span>" : ""}</header><div class="voice-shortcuts"><div><span>When you say</span><code>${escapeHtml(when)}</code><button type="button" data-copy="${escapeHtml(when)}">Copy</button></div><div><span>Alexa action</span><code>${escapeHtml(action)}</code><button type="button" data-copy="${escapeHtml(action)}">Copy</button></div></div></article>`;
          }).join("") : `<p class="empty">Set up an Apple device to create its routine.</p>`}
        </div>
      </section>
      <section class="panel">
        <header class="section-header"><h2>Recent alerts</h2></header>
        <div class="alert-list">
          ${(status.notifications ?? []).length ? status.notifications.map((note) => `
            <article class="alert-row"><strong>${escapeHtml(note.title)}</strong><span>${escapeHtml(note.body)}</span></article>
          `).join("") : `<p class="empty">No alerts yet.</p>`}
        </div>
      </section>
    </section>
  `;
  document.querySelector("#signOut")?.addEventListener("click", () => void authClient.logout({ logoutParams: { returnTo: window.location.origin } }));
  document.querySelector("#startSetup")?.addEventListener("click", () => void startSetupFlow());
  document.querySelector("#addSavedDevice")?.addEventListener("click", () => void startSetupFlow({ reuse: true }));
  document.querySelectorAll("[data-ring-device]").forEach((button) => button.addEventListener("click", async () => {
    const deviceId = button.dataset.ringDevice;
    const rowStatus = document.querySelector(`[data-device-status="${CSS.escape(deviceId)}"]`);
    if (rowStatus) rowStatus.textContent = "";
    button.disabled = true;
    button.textContent = "Ringing";
    try {
      await api("/api/ring/request", { method: "POST", body: JSON.stringify({ deviceId }) });
      if (rowStatus) rowStatus.textContent = "Ring requested.";
      window.setTimeout(() => { if (rowStatus) rowStatus.textContent = ""; }, 4000);
    } catch (error) {
      if (rowStatus) rowStatus.textContent = error.message;
    }
    button.textContent = "Ring";
    button.disabled = false;
  }));
  document.querySelector("#enablePush")?.addEventListener("click", (event) => void savePushSubscription(event.currentTarget));
  bindRenameControls();
  void updatePushState();
  bindCopyButtons();
}

function bindRenameControls() {
  const renameForm = (deviceId) => document.querySelector(`[data-rename-form="${CSS.escape(deviceId)}"]`);
  document.querySelectorAll("[data-rename-device]").forEach((button) => button.addEventListener("click", () => {
    const form = renameForm(button.dataset.renameDevice);
    if (!form) return;
    form.hidden = !form.hidden;
    if (!form.hidden) form.querySelector("input")?.focus();
  }));
  document.querySelectorAll("[data-cancel-rename]").forEach((button) => button.addEventListener("click", () => {
    const form = renameForm(button.dataset.cancelRename);
    if (form) form.hidden = true;
  }));
  document.querySelectorAll("[data-rename-form]").forEach((form) => form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const deviceId = form.dataset.renameForm;
    const status = document.querySelector(`[data-device-status="${CSS.escape(deviceId)}"]`);
    const label = new FormData(form).get("label");
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    try {
      await api(`/api/devices/${encodeURIComponent(deviceId)}/label`, { method: "POST", body: JSON.stringify({ label }) });
      await refresh();
    } catch (error) {
      button.disabled = false;
      if (status) status.textContent = error.message;
    }
  }));
}

function describeAccountDevices(account) {
  const total = Number(account.device_count ?? 0);
  const ready = Number(account.ready_device_count ?? 0);
  if (!total) return "No Apple devices";
  const noun = total === 1 ? "device" : "devices";
  if (ready === total) return `${total} ${noun} ready`;
  const state = String(account.device_status || "not_set_up").replaceAll("_", " ");
  return ready ? `${ready} of ${total} ${noun} ready · ${state}` : `${total} ${noun} · ${state}`;
}

function renderAdmin(summary, accounts, invites) {
  app.innerHTML = `
    <header class="topbar">
      <a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a>
      <nav><a class="secondary link-button" href="/">Tester app</a><button id="signOut" class="secondary" type="button">Sign out</button></nav>
    </header>
    <section class="workspace">
      <div class="panel main-panel">
        <p class="eyebrow">Owner workspace</p>
        <h1>Friends beta status.</h1>
        <p class="lede">Invites, Apple-session health, and queued renewal alerts for the private beta.</p>
      </div>
      <div class="status-grid compact">
        <article><span>Accounts</span><strong>${escapeHtml(summary.accounts)}</strong><small>Active testers</small></article>
        <article><span>Ready devices</span><strong>${escapeHtml(summary.readyDevices)}</strong><small>Healthy Find My sessions</small></article>
        <article><span>Needs attention</span><strong>${escapeHtml(summary.renewalDevices)}</strong><small>${escapeHtml(summary.queuedAlerts)} queued alerts</small></article>
      </div>
      <section class="panel">
        <header class="section-header"><h2>Add friend</h2></header>
        <form id="inviteForm" class="setup-form inline-form">
          <label>Device Finder email<input name="email" type="email" autocomplete="email" required></label>
          <label>Amazon / Alexa email<input name="amazonEmail" type="email" autocomplete="email" placeholder="Same as Device Finder if left blank"></label>
          <button class="primary" type="submit">Create invite</button>
        </form>
        <p id="inviteStatus" class="form-status"></p>
      </section>
      <section class="panel"><header class="section-header"><h2>Invites</h2></header><div class="alert-list">
        ${invites.length ? invites.map((invite) => `<article class="alert-row"><strong>${escapeHtml(invite.email)}</strong><span>Amazon: ${escapeHtml(invite.amazon_email || invite.email)} · ${escapeHtml(invite.status)}</span></article>`).join("") : `<p class="empty">No invites yet.</p>`}
      </div></section>
      <section class="panel"><header class="section-header"><h2>Accounts</h2></header><div class="alert-list">
        ${accounts.length ? accounts.map((account) => `<article class="alert-row"><strong>${escapeHtml(account.display_name || account.email)}</strong><span>${escapeHtml(account.email)} · ${escapeHtml(describeAccountDevices(account))} · Alexa ${escapeHtml(String(account.alexa_status).replaceAll("_", " "))}</span></article>`).join("") : `<p class="empty">No accounts yet.</p>`}
      </div></section>
    </section>
  `;
  document.querySelector("#signOut")?.addEventListener("click", () => void authClient.logout({ logoutParams: { returnTo: window.location.origin } }));
  document.querySelector("#inviteForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const status = document.querySelector("#inviteStatus");
    status.textContent = "Creating invite...";
    try {
      const values = new FormData(form);
      const invite = await api("/api/admin/invites", {
        method: "POST",
        body: JSON.stringify({ email: values.get("email"), amazonEmail: values.get("amazonEmail") }),
      });
      status.textContent = `Invite ready: ${invite.inviteUrl} · Amazon beta: ${invite.amazonEmail}`;
      form.reset();
      await refresh();
    } catch (error) {
      status.textContent = error.message;
    }
  });
}

async function startSetupFlow(options = {}) {
  activeSetupPoll = "";
  if (options.reuse) {
    const status = document.querySelector("#dashboardStatus");
    if (status) status.textContent = "Opening your saved Apple session...";
    try {
      const reused = await api("/api/setup/start", { method: "POST", body: JSON.stringify({ mode: "reuse" }) });
      activeSetupPoll = reused.setupId;
      renderSetupWaiting(reused.setupId, "Opening your saved Apple session...");
      pollSetup(reused.setupId);
    } catch (error) {
      if (status) status.textContent = error.message;
    }
    return;
  }
  let setup;
  try {
    setup = await api("/api/setup/start", { method: "POST", body: "{}" });
  } catch (error) {
    const status = document.querySelector("#dashboardStatus");
    if (status) status.textContent = error.message;
    else app.innerHTML = `<section class="error-panel"><strong>Setup could not start.</strong><p>${escapeHtml(error.message)}</p></section>`;
    return;
  }
  app.innerHTML = `
    <header class="topbar"><a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a></header>
    <section class="workspace setup-flow"><div class="panel main-panel">
      <p class="eyebrow">Apple setup session</p>
      <h1>Connect your Apple devices.</h1>
      <p class="lede">The live Apple relay will use these steps to create the encrypted Find My session.</p>
      <form id="setupForm" class="setup-form" autocomplete="off" data-form-type="other">
        <label>Apple account email<input name="appleId" type="email" autocomplete="off" autocapitalize="none" spellcheck="false" data-1p-ignore data-bwignore data-lpignore="true" data-protonpass-ignore="true" required></label>
        <label>Apple password<input name="password" type="password" autocomplete="off" data-1p-ignore data-bwignore data-lpignore="true" data-protonpass-ignore="true" required></label>
        <fieldset class="delivery-choice"><legend>Which code will you enter?</legend><label><input name="verificationMethod" type="radio" value="trusted_device" checked><span><strong>Apple device notification · Recommended</strong><small>Tap Allow on your trusted iPhone, iPad or Mac, then enter the code displayed there.</small></span></label><label><input name="verificationMethod" type="radio" value="sms"><span><strong>Text message fallback</strong><small>If a device prompt appears, do not interact with it. Wait for and use only the SMS code.</small></span></label></fieldset>
        <button class="primary" type="submit">Continue</button>
      </form>
      <p id="setupStatus" class="form-status"></p>
    </div></section>
  `;
  document.querySelector("#setupForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type='submit']");
    const values = new FormData(form);
    const status = document.querySelector("#setupStatus");
    button.disabled = true;
    status.textContent = "Starting secure Apple verification...";
    try {
      const verificationMethod = String(values.get("verificationMethod") || "trusted_device");
      await api(`/api/setup/${encodeURIComponent(setup.setupId)}`, {
        method: "POST",
        body: JSON.stringify({
          action: "credentials_submitted",
          appleId: values.get("appleId"),
          password: values.get("password"),
          verificationMethod,
          runnerToken: setup.runnerToken,
        }),
      });
      form.reset();
      renderWaitingForCode(setup.setupId, verificationMethod);
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
    }
  });
}

function verificationInstructions(method) {
  if (method === "trusted_device") {
    return {
      heading: "Enter the code shown on your Apple device.",
      guidance: "Apple shows this prompt on every trusted device, and twice on the device you sign in from. Approve the newest one and enter the code it displays. Do not use a text-message code for this attempt.",
      help: "If no prompt appears, start over and choose Text message instead.",
    };
  }
  return {
    heading: "Enter the code from Messages.",
    guidance: "If Apple also shows a sign-in prompt, do not tap Allow or Don’t Allow. Leave that prompt untouched and enter only the SMS code from Apple.",
    help: "If no text arrives, start over and choose Apple device notification instead.",
  };
}

function updateVerificationInstructions(method) {
  const instructions = verificationInstructions(method);
  const heading = document.querySelector("#verificationHeading");
  const guidance = document.querySelector("#verificationGuidance");
  const help = document.querySelector("#verificationHelpText");
  if (heading) heading.textContent = instructions.heading;
  if (guidance) guidance.textContent = instructions.guidance;
  if (help) help.textContent = instructions.help;
}

function renderWaitingForCode(setupId, method = "trusted_device") {
  activeSetupPoll = setupId;
  const instructions = verificationInstructions(method);
  app.innerHTML = `
    <header class="topbar"><a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a></header>
    <section class="workspace setup-flow"><div class="panel main-panel">
      <p class="eyebrow">Apple verification</p>
      <h1 id="verificationHeading">${escapeHtml(instructions.heading)}</h1>
      <p id="verificationGuidance" class="lede">${escapeHtml(instructions.guidance)}</p>
      <p id="setupMessage" class="form-status">Waiting for Apple to request verification...</p>
      <form id="codeForm" class="setup-form">
        <label>Verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
        <div class="actions"><button class="primary" type="submit">Continue</button><button id="cancelSetup" class="secondary" type="button">Start over</button></div>
      </form>
      <details class="verification-help">
        <summary>The selected code did not arrive</summary>
        <p id="verificationHelpText">${escapeHtml(instructions.help)}</p>
      </details>
    </div></section>
  `;
  document.querySelector("#codeForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type='submit']");
    const values = new FormData(form);
    button.disabled = true;
    try {
      await api(`/api/setup/${encodeURIComponent(setupId)}`, {
        method: "POST",
        body: JSON.stringify({ action: "verification_code_submitted", code: values.get("code") }),
      });
      form.reset();
      pollSetup(setupId);
    } catch (error) {
      document.querySelector("#setupMessage").textContent = error.message;
      button.disabled = false;
    }
  });
  document.querySelector("#cancelSetup")?.addEventListener("click", () => void cancelSetup(setupId));
  pollSetup(setupId);
}

async function cancelSetup(setupId) {
  activeSetupPoll = "";
  try {
    await api(`/api/setup/${encodeURIComponent(setupId)}`, { method: "POST", body: JSON.stringify({ action: "cancelled" }) });
  } catch {
    // A session that already ended needs no cancellation.
  }
  await refresh();
}

async function pollSetup(setupId, submitted = {}) {
  if (activeSetupPoll !== setupId) return;
  const status = await api(`/api/setup/${encodeURIComponent(setupId)}`);
  if (activeSetupPoll !== setupId) return;
  if (status.verification_method) updateVerificationInstructions(status.verification_method);
  const message = document.querySelector("#setupMessage");
  if (message) message.textContent = status.message || status.status;
  if (status.status === "select_device") {
    if (submitted.selection) {
      if (message) message.textContent = "Sending the test sound to your selected devices...";
      window.setTimeout(() => void pollSetup(setupId, submitted), 1000);
      return;
    }
    renderDeviceSelection(setupId, status.devices || []);
    return;
  }
  if (status.status === "test_ring_sent") {
    if (submitted.ring) {
      if (message) message.textContent = "Saving your Apple session...";
      window.setTimeout(() => void pollSetup(setupId, submitted), 1000);
      return;
    }
    renderConfirmRing(setupId, status.message);
    return;
  }
  if (status.status === "completed") {
    activeSetupPoll = "";
    await refresh();
    return;
  }
  if (status.status === "failed" || status.status === "expired") {
    activeSetupPoll = "";
    app.innerHTML = `<section class="error-panel"><strong>Setup failed.</strong><p>${escapeHtml(status.message || "Start setup again.")}</p><button id="retrySetup" class="primary" type="button">Start over</button></section>`;
    document.querySelector("#retrySetup")?.addEventListener("click", () => void refresh());
    return;
  }
  window.setTimeout(() => void pollSetup(setupId, submitted), 2500);
}

async function resumeSetupFlow(activeSetup) {
  activeSetupPoll = activeSetup.id;
  const status = await api(`/api/setup/${encodeURIComponent(activeSetup.id)}`);
  if (status.status === "select_device") {
    if (status.selected_candidate_id) {
      renderSetupWaiting(activeSetup.id, "Sending the test sound to your selected devices...");
      pollSetup(activeSetup.id, { selection: true });
      return;
    }
    renderDeviceSelection(activeSetup.id, status.devices || []);
    return;
  }
  if (status.status === "test_ring_sent") {
    if (status.confirmed_test_ring) {
      renderSetupWaiting(activeSetup.id, "Saving your Apple session...");
      pollSetup(activeSetup.id, { ring: true });
      return;
    }
    renderConfirmRing(activeSetup.id, status.message);
    return;
  }
  if (["awaiting_credentials", "awaiting_2fa"].includes(status.status)) {
    renderWaitingForCode(activeSetup.id, status.verification_method || "trusted_device");
    return;
  }
  await pollSetup(activeSetup.id);
}

function renderSetupWaiting(setupId, setupMessage) {
  app.innerHTML = `
    <header class="topbar"><a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a></header>
    <section class="workspace setup-flow"><div class="panel main-panel">
      <p class="eyebrow">Apple setup session</p>
      <h1>Setup is still running.</h1>
      <p id="setupMessage" class="form-status">${escapeHtml(setupMessage)}</p>
      <div class="actions"><button id="cancelSetup" class="secondary" type="button">Start over</button></div>
    </div></section>
  `;
  document.querySelector("#cancelSetup")?.addEventListener("click", () => void cancelSetup(setupId));
}

function renderDeviceSelection(setupId, devices) {
  activeSetupPoll = setupId;
  const nameCounts = devices.reduce((counts, device) => {
    const name = String(device.name || "Apple device");
    counts[name] = (counts[name] || 0) + 1;
    return counts;
  }, {});
  const suggestedNames = devices.map((device, index) => {
    if (device.addedAs) return device.addedAs;
    const base = nameCounts[device.name || "Apple device"] > 1 ? String(device.summary || "Apple device").split(",")[0] : String(device.name || "Apple device");
    const duplicateBefore = devices.slice(0, index).filter((candidate) => {
      const candidateBase = nameCounts[candidate.name || "Apple device"] > 1 ? String(candidate.summary || "Apple device").split(",")[0] : String(candidate.name || "Apple device");
      return candidateBase === base;
    }).length;
    return duplicateBefore ? `${base} ${duplicateBefore + 1}` : base;
  });
  const newDevices = devices.filter((device) => !device.addedAs);
  const firstNewIndex = devices.findIndex((device) => !device.addedAs);
  app.innerHTML = `
    <header class="topbar"><a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a></header>
    <section class="workspace setup-flow"><div class="panel main-panel">
      <p class="eyebrow">Select Apple devices</p>
      <h1>Choose every device Alexa may ring.</h1>
      <p class="lede">${newDevices.length
        ? "Give each one a short, different Alexa name. Devices you already added are marked."
        : "Every Apple device on this account is already set up. Select one to test or renew it."}</p>
      <form id="deviceForm" class="setup-form">
        ${devices.map((device, index) => `
          <div class="choice-row${device.addedAs ? " already-added" : ""}">
            <label class="device-check"><input name="candidateId" type="checkbox" value="${escapeHtml(device.id)}" ${index === firstNewIndex || (firstNewIndex === -1 && index === 0) ? "checked" : ""}><span><strong>${escapeHtml(device.name || "Apple device")}</strong><small>${escapeHtml(device.summary || "")}${device.addedAs ? ` · Already added as “${escapeHtml(device.addedAs)}”` : ""}</small></span></label>
            <label class="device-alias">Alexa name<input data-alias-for="${escapeHtml(device.id)}" value="${escapeHtml(suggestedNames[index])}" maxlength="80"></label>
          </div>
        `).join("")}
        <button class="primary" type="submit">Test selected devices</button>
      </form>
      <p id="deviceStatus" class="form-status"></p>
    </div></section>
  `;
  document.querySelector("#deviceForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button[type='submit']");
    const checked = [...event.currentTarget.querySelectorAll("input[name='candidateId']:checked")];
    const selectedDevices = checked.map((checkbox) => {
      const device = devices.find((candidate) => candidate.id === checkbox.value) || {};
      const alias = event.currentTarget.querySelector(`[data-alias-for="${CSS.escape(checkbox.value)}"]`);
      return { candidateId: checkbox.value, label: alias?.value.trim() || device.name || "Apple device", model: device.summary || "" };
    });
    const status = document.querySelector("#deviceStatus");
    if (!selectedDevices.length) { status.textContent = "Select at least one Apple device."; return; }
    button.disabled = true;
    try {
      await api(`/api/setup/${encodeURIComponent(setupId)}`, {
        method: "POST",
        body: JSON.stringify({ action: "device_selected", selectedDevices }),
      });
      status.textContent = "Sending the test sound...";
      pollSetup(setupId, { selection: true });
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
    }
  });
}

function renderConfirmRing(setupId, setupMessage) {
  activeSetupPoll = setupId;
  app.innerHTML = `
    <header class="topbar"><a class="brand" href="/"><span class="mark"></span><span>Device Finder</span></a></header>
    <section class="workspace setup-flow"><div class="panel main-panel">
      <p class="eyebrow">Test ring</p>
      <h1>Did every selected device play a sound?</h1>
      <p class="lede">${escapeHtml(setupMessage || "Confirm the setup test on each selected Apple device.")}</p>
      <p id="setupMessage" class="form-status"></p>
      <div class="actions"><button id="confirmRing" class="primary" type="button">Yes, finish setup</button><button id="retrySetup" class="secondary" type="button">Start over</button></div>
    </div></section>
  `;
  document.querySelector("#confirmRing").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api(`/api/setup/${encodeURIComponent(setupId)}`, { method: "POST", body: JSON.stringify({ action: "test_ring_confirmed" }) });
    } catch (error) {
      button.disabled = false;
      const status = document.querySelector("#setupMessage");
      if (status) status.textContent = error.message;
      return;
    }
    renderSetupWaiting(setupId, "Saving your Apple session...");
    pollSetup(setupId, { ring: true });
  });
  document.querySelector("#retrySetup").addEventListener("click", () => void cancelSetup(setupId));
}

function pushSupport() {
  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    const appleMobile = /iP(hone|ad|od)/.test(navigator.userAgent);
    const installed = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
    return appleMobile && !installed
      ? "iOS delivers notifications only to the installed app. Tap Share, then Add to Home Screen, open Device Finder from that icon and try again."
      : "This browser cannot subscribe to web push notifications.";
  }
  if (Notification.permission === "denied") {
    return "Notifications are blocked for Device Finder. Allow them in your browser or system settings, then try again.";
  }
  return "";
}

async function savePushSubscription(button) {
  const pushStatus = document.querySelector("#pushStatus");
  const unsupported = pushSupport();
  if (unsupported) {
    if (pushStatus) pushStatus.textContent = unsupported;
    return;
  }
  button.disabled = true;
  button.textContent = "Enabling...";
  try {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") throw new Error("Notifications were not allowed.");
    if (!config.vapidPublicKey) throw new Error("Push keys are not configured yet.");
    await navigator.serviceWorker.register("/sw.js", { scope: "/", updateViaCache: "none" });
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription() || await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64UrlToBytes(config.vapidPublicKey),
    });
    if (!subscription) throw new Error("Push could not be enabled.");
    await api("/api/push-subscriptions", { method: "POST", body: JSON.stringify({ subscription, userAgent: navigator.userAgent }) });
    button.textContent = "Notifications enabled";
    if (pushStatus) pushStatus.textContent = "This device will receive Device Finder renewal alerts.";
  } catch (error) {
    button.disabled = false;
    button.textContent = "Enable notifications";
    const rawMessage = error?.message || "Push could not be enabled.";
    const installed = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
    console.error(`Device Finder push registration failed - ${rawMessage} (installed app: ${installed ? "yes" : "no"}, permission: ${Notification.permission})`);
    if (pushStatus) {
      pushStatus.textContent = rawMessage.includes("expected pattern")
        ? "This device refused to register for push notifications. Open Device Finder from your Home Screen, then try again."
        : rawMessage;
    }
  }
}

async function updatePushState() {
  const button = document.querySelector("#enablePush");
  const pushStatus = document.querySelector("#pushStatus");
  if (!button) return;
  const unsupported = pushSupport();
  if (unsupported) {
    if (pushStatus) pushStatus.textContent = unsupported;
    return;
  }
  try {
    const registration = await navigator.serviceWorker.getRegistration("/");
    const subscription = await registration?.pushManager.getSubscription();
    if (subscription && Notification.permission === "granted") {
      button.disabled = true;
      button.textContent = "Notifications enabled";
      if (pushStatus) pushStatus.textContent = "This device will receive Device Finder renewal alerts.";
    }
  } catch {
    // The action button remains available for a user-initiated retry.
  }
}

function bindCopyButtons() {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const label = button.textContent;
      try {
        await navigator.clipboard.writeText(button.dataset.copy || "");
        button.textContent = "Copied";
      } catch {
        button.textContent = "Copy failed";
      }
      window.setTimeout(() => { button.textContent = label; }, 1200);
    });
  });
}

async function refresh() {
  try {
    if (window.location.pathname === "/admin") {
      const [summary, accountPayload, invitePayload] = await Promise.all([
        api("/api/admin/summary"),
        api("/api/admin/accounts"),
        api("/api/admin/invites"),
      ]);
      renderAdmin(summary, accountPayload.accounts ?? [], invitePayload.invites ?? []);
      return;
    }
    const status = await api("/api/status");
    if (status.activeSetup) {
      await resumeSetupFlow(status.activeSetup);
      return;
    }
    renderDashboard(status);
  } catch (error) {
    app.innerHTML = `<section class="error-panel"><strong>Could not load.</strong><p>${escapeHtml(error.message)}</p><button id="retryLoad" class="primary" type="button">Try again</button></section>`;
    document.querySelector("#retryLoad")?.addEventListener("click", () => void refresh());
  }
}

async function main() {
  await loadConfig();
  if (!config.auth0Domain) {
    renderAuthNotConfigured();
    return;
  }
  await configureAuth();
  if (!accessToken) {
    renderSignedOut();
    return;
  }
  await refresh();
}

main().catch((error) => {
  app.innerHTML = `<section class="error-panel"><strong>Could not start.</strong><p>${escapeHtml(error.message)}</p><button id="reloadApp" class="primary" type="button">Reload</button></section>`;
  document.querySelector("#reloadApp")?.addEventListener("click", () => window.location.reload());
});
