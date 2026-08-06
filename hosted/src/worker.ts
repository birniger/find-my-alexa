import { createRemoteJWKSet, jwtVerify } from "jose";
import webpush from "web-push";

type Identity = { subject: string; accessToken: string; email?: string; displayName?: string };
type Account = {
  id: string;
  authSubject: string;
  email: string;
  displayName: string;
  role: "owner" | "user";
  status: "active" | "suspended";
};
type AccountRow = {
  id: string;
  auth_subject: string;
  email: string;
  display_name: string;
  role: "owner" | "user";
  status: "active" | "suspended";
};
type DeviceRow = {
  id: string;
  label: string;
  model: string;
  apple_account_email: string;
  session_bucket: string;
  session_prefix: string;
  status: string;
  last_health_status: string;
  last_health_message: string;
  last_checked_at: string | null;
  last_renewed_at: string | null;
};
type RunnerDeviceRow = DeviceRow & { account_id: string };
type NotificationRow = {
  id: string;
  account_id: string;
  email: string;
  title: string;
  body: string;
};

class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const jsonHeaders = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), { status, headers: jsonHeaders });
const crossOriginPath = (path: string): boolean => path === "/api/config" || path.startsWith("/api/owner/");
const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type",
  "access-control-max-age": "86400",
};
const withCors = (response: Response): Response => {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(corsHeaders)) headers.set(name, value);
  return new Response(response.body, { status: response.status, headers });
};
const normalizeEmail = (value: string): string => value.trim().toLowerCase();
const auth0Issuer = (env: Env): string =>
  `https://${env.AUTH0_DOMAIN.replace(/^https?:\/\//, "").replace(/\/$/, "")}/`;
const authConfigured = (env: Env): boolean =>
  !env.AUTH0_DOMAIN.startsWith("not-configured") && !env.AUTH0_CLIENT_ID.startsWith("not-configured");

function mapAccount(row: AccountRow): Account {
  return {
    id: row.id,
    authSubject: row.auth_subject,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    status: row.status,
  };
}

async function verifyIdentity(request: Request, env: Env): Promise<Identity> {
  if (!authConfigured(env)) throw new HttpError(503, "Sign-in is not configured yet.");
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) throw new HttpError(401, "Sign in is required.");
  const issuer = auth0Issuer(env);
  const accessToken = authorization.slice(7);
  try {
    const verified = await jwtVerify(accessToken, createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`)), {
      issuer,
      audience: env.AUTH0_AUDIENCE,
      algorithms: ["RS256"],
    });
    if (typeof verified.payload.sub !== "string" || !verified.payload.sub) {
      throw new HttpError(403, "This access token has no account subject.");
    }
    return {
      subject: verified.payload.sub,
      accessToken,
      ...(typeof verified.payload.email === "string" && verified.payload.email_verified === true
        ? {
            email: verified.payload.email,
            displayName: typeof verified.payload.name === "string" ? verified.payload.name : verified.payload.email,
          }
        : {}),
    };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(401, "Your sign-in expired. Please sign in again.");
  }
}

async function resolveProfile(identity: Identity, env: Env): Promise<{ email: string; displayName: string }> {
  if (identity.email) return { email: identity.email, displayName: identity.displayName ?? identity.email };
  const response = await fetch(`${auth0Issuer(env)}userinfo`, {
    headers: { authorization: `Bearer ${identity.accessToken}` },
  });
  if (!response.ok) throw new HttpError(403, "The app could not read your verified account profile.");
  const profile = (await response.json()) as Record<string, unknown>;
  if (typeof profile.email !== "string" || profile.email_verified !== true) {
    throw new HttpError(403, "A verified email address is required.");
  }
  return { email: profile.email, displayName: typeof profile.name === "string" ? profile.name : profile.email };
}

async function ensureAccount(identity: Identity, env: Env): Promise<Account> {
  const existing = await env.DB.prepare(
    "SELECT id, auth_subject, email, display_name, role, status FROM accounts WHERE auth_subject = ?",
  )
    .bind(identity.subject)
    .first<AccountRow>();
  if (existing) {
    if (existing.status !== "active") throw new HttpError(403, "This account is suspended.");
    return mapAccount(existing);
  }

  const profile = await resolveProfile(identity, env);
  const normalizedEmail = normalizeEmail(profile.email);
  const isOwner = normalizedEmail === normalizeEmail(env.OWNER_EMAIL);
  const invite = await env.DB.prepare("SELECT id FROM invites WHERE email_normalized = ? AND status = 'pending'")
    .bind(normalizedEmail)
    .first<{ id: string }>();
  if (!isOwner && env.REGISTRATION_MODE !== "self-service" && !invite) {
    throw new HttpError(403, "This private beta requires an invitation.");
  }

  const accountId = crypto.randomUUID();
  const role = isOwner ? "owner" : "user";
  const statements = [
    env.DB.prepare(
      "INSERT INTO accounts (id, auth_subject, email, email_normalized, display_name, role) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(accountId, identity.subject, profile.email, normalizedEmail, profile.displayName, role),
    env.DB.prepare("INSERT INTO alexa_links (account_id) VALUES (?)").bind(accountId),
  ];
  if (invite) {
    statements.push(
      env.DB.prepare("UPDATE invites SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP WHERE id = ?").bind(invite.id),
    );
  }
  await env.DB.batch(statements);
  return { id: accountId, authSubject: identity.subject, email: profile.email, displayName: profile.displayName, role, status: "active" };
}

async function requireAccount(request: Request, env: Env): Promise<Account> {
  return ensureAccount(await verifyIdentity(request, env), env);
}

async function requireOwner(request: Request, env: Env): Promise<Account> {
  const account = await requireAccount(request, env);
  if (account.role !== "owner") throw new HttpError(403, "Owner access is required.");
  return account;
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  if (!(request.headers.get("content-type") ?? "").includes("application/json")) throw new HttpError(415, "Expected JSON.");
  const value = await request.json();
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "Expected a JSON object.");
  return value as Record<string, unknown>;
}

function stringField(payload: Record<string, unknown>, key: string, max = 500): string {
  const value = payload[key];
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function base64Url(bytes: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function hmac(key: ArrayBuffer | Uint8Array, value: string): Promise<ArrayBuffer> {
  const keyData = key instanceof ArrayBuffer ? key : new Uint8Array(key).buffer;
  const cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(value));
}

function sessionPrefix(accountId: string, deviceId: string): string {
  return `accounts/${accountId}/devices/${deviceId}/`;
}

function runnerQueueConfigured(env: Env): boolean {
  return Boolean(
    env.RUNNER_QUEUE_URL &&
      env.RUNNER_AWS_REGION &&
      env.RUNNER_AWS_ACCESS_KEY_ID &&
      env.RUNNER_AWS_SECRET_ACCESS_KEY &&
      env.SESSION_BUCKET,
  );
}

async function sendSqsMessage(
  env: Env,
  payload: Record<string, unknown>,
  dedupeId: string,
  messageGroupId: string,
): Promise<string | null> {
  if (!runnerQueueConfigured(env)) return null;
  const queueUrl = new URL(env.RUNNER_QUEUE_URL!);
  const isFifo = queueUrl.pathname.endsWith(".fifo");
  const form = new URLSearchParams({
    Action: "SendMessage",
    Version: "2012-11-05",
    MessageBody: JSON.stringify(payload),
  });
  if (isFifo) {
    form.set("MessageGroupId", messageGroupId);
    form.set("MessageDeduplicationId", dedupeId);
  }
  const body = form.toString();
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(body);
  const host = queueUrl.host;
  const canonicalHeaders = [
    "content-type:application/x-www-form-urlencoded",
    `host:${host}`,
    `x-amz-content-sha256:${payloadHash}`,
    `x-amz-date:${amzDate}`,
    ...(env.RUNNER_AWS_SESSION_TOKEN ? [`x-amz-security-token:${env.RUNNER_AWS_SESSION_TOKEN}`] : []),
  ].join("\n") + "\n";
  const signedHeaders = [
    "content-type",
    "host",
    "x-amz-content-sha256",
    "x-amz-date",
    ...(env.RUNNER_AWS_SESSION_TOKEN ? ["x-amz-security-token"] : []),
  ].join(";");
  const canonicalRequest = ["POST", queueUrl.pathname, queueUrl.search.slice(1), canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${env.RUNNER_AWS_REGION}/sqs/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(canonicalRequest)].join("\n");
  const kDate = await hmac(new TextEncoder().encode(`AWS4${env.RUNNER_AWS_SECRET_ACCESS_KEY}`), dateStamp);
  const kRegion = await hmac(kDate, env.RUNNER_AWS_REGION!);
  const kService = await hmac(kRegion, "sqs");
  const kSigning = await hmac(kService, "aws4_request");
  const signature = hex(await hmac(kSigning, stringToSign));
  const response = await fetch(queueUrl, {
    method: "POST",
    headers: {
      authorization: `AWS4-HMAC-SHA256 Credential=${env.RUNNER_AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
      "content-type": "application/x-www-form-urlencoded",
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
      ...(env.RUNNER_AWS_SESSION_TOKEN ? { "x-amz-security-token": env.RUNNER_AWS_SESSION_TOKEN } : {}),
    },
    body,
  });
  const text = await response.text();
  if (!response.ok) throw new HttpError(502, "The runner queue rejected the job.");
  const match = text.match(/<MessageId>([^<]+)<\/MessageId>/);
  return match?.[1] ?? null;
}

async function dispatchRunnerJob(
  env: Env,
  jobId: string,
  account: Account,
  device: RunnerDeviceRow,
  source: "web" | "alexa" | "health_check" | "setup_test",
): Promise<string | null> {
  const action = source === "health_check" ? "health_check" : "ring";
  const prefix = device.session_prefix || sessionPrefix(account.id, device.id);
  const bucket = device.session_bucket || env.SESSION_BUCKET || "";
  const messageId = await sendSqsMessage(
    env,
    {
      action,
      jobId,
      accountId: account.id,
      deviceId: device.id,
      callbackUrl: `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/api/runner/events`,
      appleId: device.apple_account_email,
      deviceName: device.label,
      sessionBucket: bucket,
      sessionPrefix: prefix,
    },
    jobId,
    account.id,
  );
  if (messageId) {
    await env.DB.prepare(
      "UPDATE ring_jobs SET dispatched_at = CURRENT_TIMESTAMP, runner_message_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
      .bind(messageId, jobId)
      .run();
  }
  return messageId;
}

async function dispatchSetupJob(
  env: Env,
  setupId: string,
  runnerToken: string,
  account: Account,
  deviceId: string,
  appleId: string,
  password: string,
  verificationMethod: "sms" | "trusted_device",
  reuse?: { bucket: string; prefix: string },
): Promise<void> {
  if (!runnerQueueConfigured(env) || !env.SETUP_QUEUE_URL) {
    throw new HttpError(503, "Apple setup relay is not configured yet.");
  }
  await sendSqsMessage(
    { ...env, RUNNER_QUEUE_URL: env.SETUP_QUEUE_URL },
    {
      action: "setup",
      setupId,
      runnerToken,
      accountId: account.id,
      deviceId,
      callbackBaseUrl: env.PUBLIC_BASE_URL.replace(/\/$/, ""),
      appleId,
      password,
      verificationMethod,
      sessionBucket: env.SESSION_BUCKET,
      sessionPrefix: sessionPrefix(account.id, deviceId),
      ...(reuse ? { mode: "reuse_session", reuseSessionBucket: reuse.bucket, reuseSessionPrefix: reuse.prefix } : {}),
    },
    setupId,
    setupId,
  );
}

async function accountDevices(env: Env, accountId: string): Promise<DeviceRow[]> {
  const result = await env.DB.prepare(
    [
      "SELECT id, label, model, status, last_health_status, last_health_message,",
      "last_checked_at, last_renewed_at, apple_account_email, session_bucket, session_prefix",
      "FROM devices WHERE account_id = ? ORDER BY created_at",
    ].join(" "),
  )
    .bind(accountId)
    .all<DeviceRow>();
  return result.results;
}

async function ensurePrimaryDevice(env: Env, accountId: string): Promise<string> {
  const existing = await env.DB.prepare("SELECT id FROM devices WHERE account_id = ? ORDER BY created_at LIMIT 1")
    .bind(accountId)
    .first<{ id: string }>();
  if (existing) return existing.id;
  const deviceId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO devices (id, account_id, label) VALUES (?, ?, ?)").bind(deviceId, accountId, "").run();
  return deviceId;
}

async function statusPayload(env: Env, account: Account): Promise<Record<string, unknown>> {
  const [devices, alexa, notifications, activeSetup] = await Promise.all([
    accountDevices(env, account.id),
    env.DB.prepare("SELECT status, linked_at FROM alexa_links WHERE account_id = ?")
      .bind(account.id)
      .first<{ status: string; linked_at: string | null }>(),
    env.DB.prepare(
      "SELECT id, kind, delivery_status, title, body, created_at FROM notification_events WHERE account_id = ? ORDER BY created_at DESC LIMIT 10",
    )
      .bind(account.id)
      .all(),
    env.DB.prepare(
      [
        "SELECT id, status, message, verification_method FROM setup_sessions",
        "WHERE account_id = ? AND status NOT IN ('completed', 'failed', 'expired')",
        "AND runner_started_at IS NOT NULL AND datetime(expires_at) > CURRENT_TIMESTAMP",
        "ORDER BY created_at DESC LIMIT 1",
      ].join(" "),
    ).bind(account.id).first(),
  ]);
  return {
    account,
    alexa: alexa ?? { status: "unlinked", linked_at: null },
    devices,
    notifications: notifications.results,
    activeSetup: activeSetup ?? null,
  };
}

// A dispatch failure after runner_started_at is set would leave a session the
// dashboard resumes into forever, so the session is closed before rethrowing.
async function dispatchOrCloseSession(env: Env, setupId: string, dispatch: () => Promise<void>): Promise<void> {
  try {
    await dispatch();
  } catch (error) {
    await env.DB.prepare(
      [
        "UPDATE setup_sessions SET status = 'failed', runner_token_hash = '',",
        "message = 'The Apple setup relay could not be reached. Start setup again.',",
        "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      ].join(" "),
    )
      .bind(setupId)
      .run();
    throw error;
  }
}

async function reusableSession(env: Env, accountId: string): Promise<{ bucket: string; prefix: string; appleId: string } | null> {
  const device = await env.DB.prepare(
    [
      "SELECT apple_account_email, session_bucket, session_prefix FROM devices",
      "WHERE account_id = ? AND status = 'ready' AND session_bucket != '' AND session_prefix != ''",
      "AND apple_account_email != '' ORDER BY last_renewed_at DESC LIMIT 1",
    ].join(" "),
  )
    .bind(accountId)
    .first<{ apple_account_email: string; session_bucket: string; session_prefix: string }>();
  if (!device) return null;
  return { bucket: device.session_bucket, prefix: device.session_prefix, appleId: device.apple_account_email };
}

async function handleSetupStart(request: Request, env: Env, account: Account): Promise<Response> {
  const payload = await readJson(request).catch(() => ({} as Record<string, unknown>));
  const reuseRequested = stringField(payload, "mode", 40) === "reuse";
  const reuse = reuseRequested ? await reusableSession(env, account.id) : null;
  if (reuseRequested && !reuse) {
    throw new HttpError(409, "No saved Apple session is available yet. Choose Set up devices to sign in to Apple.");
  }
  const deviceId = await ensurePrimaryDevice(env, account.id);
  const setupId = crypto.randomUUID();
  const runnerToken = crypto.randomUUID();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(runnerToken));
  const runnerTokenHash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  await env.DB.batch([
    env.DB.prepare(
      [
        "UPDATE setup_sessions SET status = 'expired', verification_code = '', selected_candidate_id = '',",
        "confirmed_test_ring = 0, message = 'A newer setup session was started.', updated_at = CURRENT_TIMESTAMP",
        "WHERE account_id = ? AND status NOT IN ('completed', 'failed', 'expired')",
      ].join(" "),
    ).bind(account.id),
    env.DB.prepare(
      "INSERT INTO setup_sessions (id, account_id, device_id, runner_token_hash, expires_at) VALUES (?, ?, ?, ?, ?)",
    ).bind(setupId, account.id, deviceId, runnerTokenHash, expires),
  ]);
  if (reuse) {
    await env.DB.prepare(
      [
        "UPDATE setup_sessions SET apple_account_email = ?, message = 'Opening your saved Apple session.',",
        "runner_started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      ].join(" "),
    )
      .bind(reuse.appleId, setupId)
      .run();
    await dispatchOrCloseSession(env, setupId, () =>
      dispatchSetupJob(env, setupId, runnerToken, account, deviceId, reuse.appleId, "", "trusted_device", {
        bucket: reuse.bucket,
        prefix: reuse.prefix,
      }),
    );
    return json({ setupId, deviceId, expiresAt: expires, runnerToken, next: "select_device" });
  }
  return json({ setupId, deviceId, expiresAt: expires, runnerToken, next: "credentials" });
}

async function handleSetupUpdate(request: Request, env: Env, account: Account, setupId: string): Promise<Response> {
  const payload = await readJson(request);
  const action = stringField(payload, "action", 80);
  const session = await env.DB.prepare(
    "SELECT id, status, device_id, expires_at FROM setup_sessions WHERE id = ? AND account_id = ?",
  )
    .bind(setupId, account.id)
    .first<{ id: string; status: string; device_id: string | null; expires_at: string }>();
  if (!session) throw new HttpError(404, "Setup session not found.");
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare(
      "UPDATE setup_sessions SET status = 'expired', verification_code = '', selected_candidate_id = '', confirmed_test_ring = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
      .bind(setupId)
      .run();
    throw new HttpError(410, "This setup session expired. Start setup again.");
  }
  if (["completed", "failed", "expired"].includes(session.status)) {
    throw new HttpError(409, "This setup session has ended. Start setup again.");
  }

  if (action === "credentials_submitted") {
    if (session.status !== "awaiting_credentials") throw new HttpError(409, "Apple setup is already in progress.");
    if (!session.device_id) throw new HttpError(409, "No device is attached to this setup session.");
    const appleId = stringField(payload, "appleId", 320);
    const password = stringField(payload, "password", 2000);
    const requestedVerificationMethod = stringField(payload, "verificationMethod", 40);
    const verificationMethod = requestedVerificationMethod === "sms" ? "sms" : "trusted_device";
    const runnerToken = stringField(payload, "runnerToken", 120);
    if (!appleId || !appleId.includes("@")) throw new HttpError(400, "A valid Apple account email is required.");
    if (!password) throw new HttpError(400, "Apple password is required for this live setup attempt.");
    if (!runnerToken) throw new HttpError(403, "Setup token is required.");
    const runnerTokenHash = await sha256Hex(runnerToken);
    const tokenMatch = await env.DB.prepare("SELECT id FROM setup_sessions WHERE id = ? AND runner_token_hash = ?")
      .bind(setupId, runnerTokenHash)
      .first<{ id: string }>();
    if (!tokenMatch) throw new HttpError(403, "Setup token is invalid.");
    await env.DB.batch([
      env.DB.prepare(
        [
          "UPDATE setup_sessions SET status = 'awaiting_credentials', apple_account_email = ?,",
          "verification_method = ?, message = 'Starting Apple setup relay.',",
          "runner_started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        ].join(" "),
      ).bind(appleId, verificationMethod, setupId),
    ]);
    await dispatchOrCloseSession(env, setupId, () =>
      dispatchSetupJob(env, setupId, runnerToken, account, session.device_id as string, appleId, password, verificationMethod),
    );
    return json({ status: "awaiting_2fa" });
  }
  if (action === "verification_code_submitted") {
    if (!['awaiting_credentials', 'awaiting_2fa'].includes(session.status)) {
      throw new HttpError(409, "Apple is not waiting for a verification code.");
    }
    const code = stringField(payload, "code", 20).replace(/\s+/g, "");
    if (!/^\d{4,8}$/.test(code)) throw new HttpError(400, "A valid Apple verification code is required.");
    await env.DB.prepare(
      "UPDATE setup_sessions SET verification_code = ?, message = 'Verification code received.', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
      .bind(code, setupId)
      .run();
    return json({ status: "code_received" });
  }
  if (action === "device_selected") {
    if (session.status !== "select_device") throw new HttpError(409, "Apple is not waiting for a device selection.");
    const requestedDevices = Array.isArray(payload.selectedDevices) ? payload.selectedDevices.slice(0, 8) : [];
    const selections = requestedDevices.flatMap((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return [];
      const row = value as Record<string, unknown>;
      const candidateId = stringField(row, "candidateId", 40);
      const label = stringField(row, "label", 80) || "Apple device";
      const model = stringField(row, "model", 120);
      return candidateId ? [{ candidateId, label, model }] : [];
    });
    if (!selections.length) throw new HttpError(400, "Select at least one Apple device.");
    if (new Set(selections.map((selection) => selection.candidateId)).size !== selections.length) {
      throw new HttpError(400, "Each Apple device can only be selected once.");
    }
    if (new Set(selections.map((selection) => selection.label.toLowerCase())).size !== selections.length) {
      throw new HttpError(400, "Give each selected Apple device a different Alexa name.");
    }

    const existing = await env.DB.prepare(
      "SELECT id, apple_device_hint, label FROM devices WHERE account_id = ? ORDER BY created_at",
    ).bind(account.id).all<{ id: string; apple_device_hint: string; label: string }>();
    if (selections.some((selection) => existing.results.some(
      (device) => device.apple_device_hint !== selection.candidateId && device.label.toLowerCase() === selection.label.toLowerCase(),
    ))) {
      throw new HttpError(400, "That Alexa name is already used by another Apple device.");
    }
    let placeholderUsed = false;
    const selectedDevices = selections.map((selection) => {
      const matched = existing.results.find((device) => device.apple_device_hint === selection.candidateId);
      const reusablePlaceholder = placeholderUsed ? undefined : existing.results.find(
        (device) => device.id === session.device_id && !device.apple_device_hint,
      );
      if (reusablePlaceholder) placeholderUsed = true;
      const deviceId = matched?.id || reusablePlaceholder?.id || crypto.randomUUID();
      const prefix = sessionPrefix(account.id, deviceId);
      return {
        ...selection,
        deviceId,
        sessionBucket: env.SESSION_BUCKET || "",
        sessionPrefix: prefix,
      };
    });
    const appleId = await env.DB.prepare("SELECT apple_account_email FROM setup_sessions WHERE id = ?")
      .bind(setupId)
      .first<{ apple_account_email: string }>();
    const deviceStatements = selectedDevices.map((selection) => {
      const exists = existing.results.some((device) => device.id === selection.deviceId);
      return exists
        ? env.DB.prepare(
            [
              "UPDATE devices SET label = ?, model = ?, apple_device_hint = ?, apple_account_email = ?,",
              "session_bucket = ?, session_prefix = ?, status = 'setup_pending', updated_at = CURRENT_TIMESTAMP",
              "WHERE id = ? AND account_id = ?",
            ].join(" "),
          ).bind(selection.label, selection.model, selection.candidateId, appleId?.apple_account_email || "", selection.sessionBucket, selection.sessionPrefix, selection.deviceId, account.id)
        : env.DB.prepare(
            [
              "INSERT INTO devices (id, account_id, label, model, apple_device_hint, apple_account_email,",
              "session_bucket, session_prefix, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'setup_pending')",
            ].join(" "),
          ).bind(selection.deviceId, account.id, selection.label, selection.model, selection.candidateId, appleId?.apple_account_email || "", selection.sessionBucket, selection.sessionPrefix);
    });
    await env.DB.batch([
      ...deviceStatements,
      env.DB.prepare(
        [
          "UPDATE setup_sessions SET device_id = ?, selected_candidate_id = ?, selected_devices_json = ?,",
          "message = 'Apple devices selected.', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        ].join(" "),
      ).bind(selectedDevices[0].deviceId, selectedDevices[0].candidateId, JSON.stringify(selectedDevices), setupId),
    ]);
    return json({ status: "device_selected", deviceIds: selectedDevices.map((selection) => selection.deviceId) });
  }
  if (action === "cancelled") {
    const selection = await env.DB.prepare("SELECT selected_devices_json FROM setup_sessions WHERE id = ?")
      .bind(setupId)
      .first<{ selected_devices_json: string }>();
    const pendingDeviceIds = (() => {
      try {
        const selected = JSON.parse(selection?.selected_devices_json || "[]") as Array<{ deviceId?: unknown }>;
        const ids = selected.flatMap((value) => (typeof value.deviceId === "string" && value.deviceId ? [value.deviceId] : []));
        if (ids.length) return [...new Set(ids)];
      } catch {
        // Fall back to the session device below.
      }
      return [session.device_id || ""].filter(Boolean);
    })();
    await env.DB.batch([
      env.DB.prepare(
        [
          "UPDATE setup_sessions SET status = 'expired', verification_code = '', selected_candidate_id = '',",
          "selected_devices_json = '[]', confirmed_test_ring = 0, runner_token_hash = '',",
          "message = 'Setup was cancelled.', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        ].join(" "),
      ).bind(setupId),
      ...pendingDeviceIds.map((pendingDeviceId) => env.DB.prepare(
        [
          "UPDATE devices SET status = CASE WHEN last_renewed_at IS NULL THEN 'not_set_up' ELSE 'needs_renewal' END,",
          "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_id = ? AND status = 'setup_pending'",
        ].join(" "),
      ).bind(pendingDeviceId, account.id)),
    ]);
    return json({ status: "expired" });
  }
  if (action === "test_ring_confirmed") {
    if (session.status !== "test_ring_sent") throw new HttpError(409, "A test ring is not waiting for confirmation.");
    if (!session.device_id) throw new HttpError(409, "No device is attached to this setup session.");
    await env.DB.prepare(
      "UPDATE setup_sessions SET confirmed_test_ring = 1, message = 'Test ring confirmed.', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
      .bind(setupId)
      .run();
    return json({ status: "confirmed" });
  }
  throw new HttpError(400, "Unsupported setup action.");
}

async function handleDeviceRename(request: Request, env: Env, account: Account, deviceId: string): Promise<Response> {
  const payload = await readJson(request);
  const label = stringField(payload, "label", 80);
  if (!label) throw new HttpError(400, "An Alexa name is required.");
  const devices = await env.DB.prepare("SELECT id, label FROM devices WHERE account_id = ?")
    .bind(account.id)
    .all<{ id: string; label: string }>();
  if (!devices.results.some((device) => device.id === deviceId)) throw new HttpError(404, "Device not found.");
  if (devices.results.some((device) => device.id !== deviceId && device.label.toLowerCase() === label.toLowerCase())) {
    throw new HttpError(400, "That Alexa name is already used by another Apple device.");
  }
  await env.DB.prepare("UPDATE devices SET label = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_id = ?")
    .bind(label, deviceId, account.id)
    .run();
  return json({ id: deviceId, label });
}

async function handleSetupStatus(env: Env, account: Account, setupId: string): Promise<Response> {
  const setup = await env.DB.prepare(
    [
      "SELECT id, status, message, device_candidates_json, selected_candidate_id,",
      "confirmed_test_ring, verification_method, updated_at FROM setup_sessions WHERE id = ? AND account_id = ?",
    ].join(" "),
  )
    .bind(setupId, account.id)
    .first<Record<string, unknown>>();
  if (!setup) throw new HttpError(404, "Setup session not found.");
  const candidates = JSON.parse(
    typeof setup.device_candidates_json === "string" ? setup.device_candidates_json : "[]",
  ) as Array<Record<string, unknown>>;
  // Apple returns every Find My device, so already-configured ones are marked
  // rather than offered again as if they were new.
  const claimed = await env.DB.prepare(
    "SELECT apple_device_hint, label FROM devices WHERE account_id = ? AND apple_device_hint != ''",
  )
    .bind(account.id)
    .all<{ apple_device_hint: string; label: string }>();
  const claimedByHint = new Map(claimed.results.map((device) => [device.apple_device_hint, device.label]));
  return json({
    ...setup,
    devices: candidates.map((candidate) => {
      const existingLabel = claimedByHint.get(String(candidate.id ?? ""));
      return existingLabel === undefined ? candidate : { ...candidate, addedAs: existingLabel };
    }),
  });
}

async function handleRingRequest(
  request: Request,
  env: Env,
  account: Account,
  source: "web" | "alexa" | "health_check" | "setup_test",
): Promise<Response> {
  const payload = await readJson(request);
  const requestedDeviceId = stringField(payload, "deviceId", 80);
  const requestedDeviceName = stringField(payload, "deviceName", 120).toLowerCase();
  // A ring that arrives with an Alexa-linked token is the only proof account
  // linking succeeded, so it is what marks the link as live.
  const requestSource = source === "web" && stringField(payload, "source", 20) === "alexa" ? "alexa" : source;
  if (requestSource === "alexa") {
    await env.DB.prepare(
      "UPDATE alexa_links SET status = 'linked', linked_at = COALESCE(linked_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP WHERE account_id = ?",
    )
      .bind(account.id)
      .run();
  }
  const devices = await env.DB.prepare(
    [
      "SELECT id, account_id, label, model, status, last_health_status, last_health_message,",
      "last_checked_at, last_renewed_at, apple_account_email, session_bucket, session_prefix",
      "FROM devices WHERE account_id = ? ORDER BY created_at",
    ].join(" "),
  )
    .bind(account.id)
    .all<RunnerDeviceRow>();
  const readyDevices = devices.results.filter((device) => device.status === "ready");
  const device = requestedDeviceId
    ? readyDevices.find((candidate) => candidate.id === requestedDeviceId)
    : requestedDeviceName
      ? readyDevices.find((candidate) => candidate.label.toLowerCase() === requestedDeviceName)
      : readyDevices[0];
  if (!device) {
    if (requestedDeviceName || requestedDeviceId) throw new HttpError(404, "That Apple device is not ready in Device Finder.");
    throw new HttpError(409, "Your Apple device setup needs renewal before it can ring.");
  }
  if (!device.apple_account_email || !device.session_prefix) {
    throw new HttpError(409, "Your Apple device setup is incomplete. Please renew setup.");
  }
  const jobId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO ring_jobs (id, account_id, device_id, source) VALUES (?, ?, ?, ?)")
    .bind(jobId, account.id, device.id, requestSource)
    .run();
  const messageId = await dispatchRunnerJob(env, jobId, account, device, requestSource);
  return json({ jobId, status: "queued", dispatched: Boolean(messageId), deviceId: device.id, deviceLabel: device.label }, 202);
}

async function handlePushUnsubscribe(request: Request, env: Env, account: Account): Promise<Response> {
  const payload = await readJson(request);
  const endpoint = stringField(payload, "endpoint", 1000);
  if (!endpoint) throw new HttpError(400, "A push endpoint is required.");
  const result = await env.DB.prepare(
    "UPDATE push_subscriptions SET status = 'revoked', updated_at = CURRENT_TIMESTAMP WHERE account_id = ? AND endpoint = ?",
  )
    .bind(account.id, endpoint)
    .run();
  return json({ status: "revoked", removed: Boolean(result.meta.changes) });
}

async function handlePushSubscription(request: Request, env: Env, account: Account): Promise<Response> {
  const payload = await readJson(request);
  const subscription = payload.subscription;
  if (!subscription || typeof subscription !== "object" || Array.isArray(subscription)) {
    throw new HttpError(400, "A push subscription is required.");
  }
  const endpoint = typeof (subscription as Record<string, unknown>).endpoint === "string" ? (subscription as Record<string, unknown>).endpoint : "";
  if (!endpoint) throw new HttpError(400, "A push endpoint is required.");
  await env.DB.prepare(
    [
      "INSERT INTO push_subscriptions (id, account_id, endpoint, subscription_json, user_agent)",
      "VALUES (?, ?, ?, ?, ?)",
      "ON CONFLICT(endpoint) DO UPDATE SET subscription_json = excluded.subscription_json,",
      "user_agent = excluded.user_agent, status = 'active', updated_at = CURRENT_TIMESTAMP",
    ].join(" "),
  )
    .bind(crypto.randomUUID(), account.id, endpoint, JSON.stringify(subscription), stringField(payload, "userAgent", 500))
    .run();
  return json({ status: "active" });
}

async function sendPushNotification(env: Env, accountId: string, title: string, body: string): Promise<boolean> {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) return false;
  webpush.setVapidDetails(
    env.VAPID_SUBJECT || `mailto:${env.OWNER_EMAIL}`,
    env.VAPID_PUBLIC_KEY,
    env.VAPID_PRIVATE_KEY,
  );
  const result = await env.DB.prepare(
    "SELECT id, subscription_json FROM push_subscriptions WHERE account_id = ? AND status = 'active'",
  )
    .bind(accountId)
    .all<{ id: string; subscription_json: string }>();
  let delivered = false;
  for (const subscription of result.results) {
    try {
      await webpush.sendNotification(
        JSON.parse(subscription.subscription_json),
        JSON.stringify({ title, body, url: "/" }),
        { TTL: 24 * 60 * 60 },
      );
      delivered = true;
    } catch {
      await env.DB.prepare("UPDATE push_subscriptions SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(subscription.id)
        .run();
    }
  }
  return delivered;
}

async function sendEmailNotification(env: Env, email: string, title: string, body: string): Promise<boolean> {
  if (!env.EMAIL || !env.EMAIL_FROM) return false;
  await env.EMAIL.send({
    to: email,
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME || "Device Finder" },
    subject: title,
    html: `<p>${body.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")}</p>`,
    text: body,
  });
  return true;
}

async function deliverQueuedNotifications(env: Env, accountId?: string): Promise<void> {
  const result = await env.DB.prepare(
    [
      "SELECT n.id, n.account_id, a.email, n.title, n.body",
      "FROM notification_events n",
      "JOIN accounts a ON a.id = n.account_id",
      "WHERE n.delivery_status = 'queued'",
      accountId ? "AND n.account_id = ?" : "",
      "ORDER BY n.created_at LIMIT 25",
    ].join(" "),
  )
    .bind(...(accountId ? [accountId] : []))
    .all<NotificationRow>();

  for (const notification of result.results) {
    try {
      if (await sendPushNotification(env, notification.account_id, notification.title, notification.body)) {
        await env.DB.prepare(
          "UPDATE notification_events SET delivery_status = 'push_sent', delivered_at = CURRENT_TIMESTAMP WHERE id = ?",
        )
          .bind(notification.id)
          .run();
        continue;
      }
      if (await sendEmailNotification(env, notification.email, notification.title, notification.body)) {
        await env.DB.prepare(
          "UPDATE notification_events SET delivery_status = 'email_sent', delivered_at = CURRENT_TIMESTAMP WHERE id = ?",
        )
          .bind(notification.id)
          .run();
        continue;
      }
      await env.DB.prepare("UPDATE notification_events SET delivery_status = 'failed' WHERE id = ?").bind(notification.id).run();
    } catch {
      await env.DB.prepare("UPDATE notification_events SET delivery_status = 'failed' WHERE id = ?").bind(notification.id).run();
    }
  }
}

async function enqueueDailyHealthChecks(env: Env): Promise<void> {
  const result = await env.DB.prepare(
    [
      "SELECT id, account_id, label, model, status, last_health_status, last_health_message,",
      "last_checked_at, last_renewed_at, apple_account_email, session_bucket, session_prefix",
      "FROM devices",
      "WHERE status = 'ready'",
      "AND (last_checked_at IS NULL OR last_checked_at < datetime('now', '-20 hours'))",
      "LIMIT 50",
    ].join(" "),
  ).all<RunnerDeviceRow>();

  for (const device of result.results) {
    const account = await env.DB.prepare(
      "SELECT id, auth_subject, email, display_name, role, status FROM accounts WHERE id = ? AND status = 'active'",
    )
      .bind(device.account_id)
      .first<AccountRow>();
    if (!account) continue;
    const jobId = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO ring_jobs (id, account_id, device_id, source) VALUES (?, ?, ?, 'health_check')")
      .bind(jobId, device.account_id, device.id)
      .run();
    await dispatchRunnerJob(env, jobId, mapAccount(account), device, "health_check");
  }
}

async function handleAdminSummary(env: Env): Promise<Response> {
  const [accounts, readyDevices, renewalDevices, queuedAlerts, failedJobs] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) AS count FROM accounts WHERE status = 'active'").first<{ count: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM devices WHERE status = 'ready'").first<{ count: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM devices WHERE status IN ('needs_renewal', 'unhealthy')").first<{ count: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM notification_events WHERE delivery_status = 'queued'").first<{ count: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM ring_jobs WHERE status = 'failed'").first<{ count: number }>(),
  ]);
  return json({
    accounts: accounts?.count ?? 0,
    readyDevices: readyDevices?.count ?? 0,
    renewalDevices: renewalDevices?.count ?? 0,
    queuedAlerts: queuedAlerts?.count ?? 0,
    failedJobs: failedJobs?.count ?? 0,
  });
}

async function handleAdminAccounts(env: Env): Promise<Response> {
  const result = await env.DB.prepare(
    [
      // Correlated subqueries keep this one row per account; joining devices
      // repeated an account once per device.
      "SELECT a.id, a.email, a.display_name, a.role, a.status, a.created_at,",
      // Most urgent status first: an admin needs the device that needs help.
      "COALESCE((SELECT d.status FROM devices d WHERE d.account_id = a.id",
      "  ORDER BY CASE d.status WHEN 'needs_renewal' THEN 0 WHEN 'unhealthy' THEN 1",
      "    WHEN 'not_set_up' THEN 2 WHEN 'setup_pending' THEN 3 ELSE 4 END, d.created_at LIMIT 1), 'not_set_up') AS device_status,",
      "(SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id) AS device_count,",
      "(SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id AND d.status = 'ready') AS ready_device_count,",
      "COALESCE((SELECT l.status FROM alexa_links l WHERE l.account_id = a.id LIMIT 1), 'unlinked') AS alexa_status",
      "FROM accounts a",
      "ORDER BY a.created_at DESC",
    ].join(" "),
  ).all();
  return json({ accounts: result.results });
}

async function handleAdminInvites(env: Env): Promise<Response> {
  const result = await env.DB.prepare(
    "SELECT id, email, amazon_email, status, created_at, accepted_at FROM invites ORDER BY created_at DESC",
  ).all();
  return json({ invites: result.results });
}

async function handleCreateInvite(request: Request, env: Env, owner: Account): Promise<Response> {
  const payload = await readJson(request);
  const email = stringField(payload, "email", 320);
  const amazonEmail = stringField(payload, "amazonEmail", 320) || email;
  if (!email || !email.includes("@")) throw new HttpError(400, "A valid email is required.");
  if (!amazonEmail.includes("@")) throw new HttpError(400, "A valid Amazon account email is required.");
  const id = crypto.randomUUID();
  await env.DB.prepare(
    [
      "INSERT INTO invites (id, email, email_normalized, amazon_email, amazon_email_normalized, invited_by) VALUES (?, ?, ?, ?, ?, ?)",
      "ON CONFLICT(email_normalized) DO UPDATE SET amazon_email = excluded.amazon_email,",
      "amazon_email_normalized = excluded.amazon_email_normalized, status = 'pending', invited_by = excluded.invited_by",
    ].join(" "),
  )
    .bind(id, email, normalizeEmail(email), amazonEmail, normalizeEmail(amazonEmail), owner.id)
    .run();
  return json({ id, email, amazonEmail, inviteUrl: `${env.PUBLIC_BASE_URL}/?invite=${encodeURIComponent(email)}` }, 201);
}

function myBuildsAuthorized(request: Request, env: Env): boolean {
  return !!env.MY_BUILDS_STATUS_TOKEN &&
    request.headers.get("authorization") === `Bearer ${env.MY_BUILDS_STATUS_TOKEN}`;
}

async function handleOwnerStatus(request: Request, env: Env): Promise<Response> {
  if (!myBuildsAuthorized(request, env)) throw new HttpError(403, "Status token is invalid.");
  const owner = await env.DB.prepare(
    "SELECT id FROM accounts WHERE email_normalized = ? AND role = 'owner' AND status = 'active'",
  ).bind(normalizeEmail(env.OWNER_EMAIL)).first<{ id: string }>();
  const summaryResponse = await handleAdminSummary(env);
  const summary = await summaryResponse.json() as Record<string, unknown>;
  return json({ ...summary, ownerReady: Boolean(owner) });
}

async function handleOwnerPushSubscription(request: Request, env: Env): Promise<Response> {
  if (!myBuildsAuthorized(request, env)) throw new HttpError(403, "Status token is invalid.");
  const owner = await env.DB.prepare(
    "SELECT id, auth_subject, email, display_name, role, status FROM accounts WHERE email_normalized = ? AND role = 'owner'",
  )
    .bind(normalizeEmail(env.OWNER_EMAIL))
    .first<AccountRow>();
  if (!owner) throw new HttpError(409, "Open Device Finder and sign in once before enabling owner alerts.");
  return handlePushSubscription(request, env, mapAccount(owner));
}

function runnerAuthorized(request: Request, env: Env): boolean {
  const token = env.RUNNER_API_TOKEN?.trim();
  return !!token && (
    request.headers.get("authorization") === `Bearer ${token}` ||
    request.headers.get("x-runner-token")?.trim() === token
  );
}

async function handleRunnerJobs(request: Request, env: Env): Promise<Response> {
  if (!runnerAuthorized(request, env)) throw new HttpError(403, "Runner token is invalid.");
  const result = await env.DB.prepare(
    "SELECT id, account_id, device_id, source, created_at FROM ring_jobs WHERE status = 'queued' ORDER BY created_at LIMIT 10",
  ).all();
  return json({ jobs: result.results });
}

async function handleRunnerEvent(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (!runnerAuthorized(request, env)) throw new HttpError(403, "Runner token is invalid.");
  const payload = await readJson(request);
  const accountId = stringField(payload, "accountId", 80);
  const deviceId = stringField(payload, "deviceId", 80);
  const jobId = stringField(payload, "jobId", 80);
  const status = stringField(payload, "status", 40);
  const message = stringField(payload, "message", 500);
  const setupId = stringField(payload, "setupId", 80);
  if (setupId) {
    const devices = Array.isArray(payload.devices) ? JSON.stringify(payload.devices).slice(0, 20_000) : "";
    const setupStatus = stringField(payload, "setupStatus", 80) || status;
    const reportedVerificationMethod = stringField(payload, "verificationMethod", 40);
    const verificationMethod = ["sms", "trusted_device"].includes(reportedVerificationMethod)
      ? reportedVerificationMethod
      : "";
    const statement = devices
      ? env.DB.prepare(
          [
            "UPDATE setup_sessions SET status = ?, message = ?, device_candidates_json = ?, verification_method = CASE WHEN ? = '' THEN verification_method ELSE ? END,",
            "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
          ].join(" "),
        ).bind(setupStatus, message, devices, verificationMethod, verificationMethod, setupId)
      : env.DB.prepare(
          "UPDATE setup_sessions SET status = ?, message = ?, verification_method = CASE WHEN ? = '' THEN verification_method ELSE ? END, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        ).bind(setupStatus, message, verificationMethod, verificationMethod, setupId);
    const statements = [statement];
    const setupSelection = await env.DB.prepare(
      "SELECT device_id, selected_devices_json, status FROM setup_sessions WHERE id = ?",
    ).bind(setupId).first<{ device_id: string | null; selected_devices_json: string; status: string }>();
    if (!setupSelection || ["completed", "failed", "expired"].includes(setupSelection.status)) {
      return json({ ok: true, ignored: true });
    }
    const selectedDeviceIds = (() => {
      if (Array.isArray(payload.deviceIds)) {
        const ids = payload.deviceIds.filter((value): value is string => typeof value === "string" && Boolean(value));
        if (ids.length) return [...new Set(ids)];
      }
      try {
        const selected = JSON.parse(setupSelection?.selected_devices_json || "[]") as Array<{ deviceId?: unknown }>;
        const ids = selected.flatMap((value) => typeof value.deviceId === "string" && value.deviceId ? [value.deviceId] : []);
        if (ids.length) return [...new Set(ids)];
      } catch {
        // Fall back to the primary device below.
      }
      return [deviceId || setupSelection?.device_id || ""].filter(Boolean);
    })();
    if (setupStatus === "completed" && accountId && selectedDeviceIds.length) {
      statements.push(
        env.DB.prepare(
          [
            "UPDATE setup_sessions SET verification_code = '', selected_candidate_id = '', selected_devices_json = '[]', confirmed_test_ring = 0,",
            "runner_token_hash = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
          ].join(" "),
        ).bind(setupId),
      );
      for (const completedDeviceId of selectedDeviceIds) {
        statements.push(
          env.DB.prepare(
            [
              "UPDATE devices SET status = 'ready', last_health_status = 'healthy',",
              "last_health_message = '', last_checked_at = CURRENT_TIMESTAMP, last_renewed_at = CURRENT_TIMESTAMP,",
              "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_id = ?",
            ].join(" "),
          ).bind(completedDeviceId, accountId),
          env.DB.prepare(
            "UPDATE notification_events SET delivery_status = 'dismissed' WHERE account_id = ? AND device_id = ? AND kind = 'renewal_required' AND delivery_status IN ('queued', 'push_sent', 'email_sent')",
          ).bind(accountId, completedDeviceId),
        );
      }
    } else if (["failed", "expired"].includes(setupStatus)) {
      statements.push(
        env.DB.prepare(
          [
            "UPDATE setup_sessions SET verification_code = '', selected_candidate_id = '', selected_devices_json = '[]', confirmed_test_ring = 0,",
            "runner_token_hash = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
          ].join(" "),
        ).bind(setupId),
      );
      if (accountId) {
        for (const failedDeviceId of selectedDeviceIds) {
          statements.push(env.DB.prepare(
            [
              "UPDATE devices SET status = CASE WHEN last_renewed_at IS NULL THEN 'not_set_up' ELSE 'needs_renewal' END,",
              "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_id = ? AND status = 'setup_pending'",
            ].join(" "),
          ).bind(failedDeviceId, accountId));
        }
      }
    }
    await env.DB.batch(statements);
    return json({ ok: true });
  }
  if (jobId && ["running", "succeeded", "failed", "reauthentication_required", "healthy"].includes(status)) {
    const jobStatus = status === "healthy" ? "succeeded" : status === "reauthentication_required" ? "failed" : status;
    await env.DB.prepare("UPDATE ring_jobs SET status = ?, message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(jobStatus, message, jobId)
      .run();
  }
  if (accountId && deviceId && status === "healthy") {
    await env.DB.batch([
      env.DB.prepare(
        [
          "INSERT INTO notification_events (id, account_id, device_id, kind, delivery_status, title, body)",
          "SELECT ?, ?, ?, 'health_recovered', 'dismissed', ?, ? FROM devices",
          "WHERE id = ? AND account_id = ? AND last_health_status != 'healthy'",
        ].join(" "),
      ).bind(
        crypto.randomUUID(),
        accountId,
        deviceId,
        "Apple login recovered",
        "Find My access is healthy again.",
        deviceId,
        accountId,
      ),
      env.DB.prepare(
        [
          "UPDATE devices SET status = 'ready', last_health_status = 'healthy',",
          "last_health_message = '', last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
          "WHERE id = ? AND account_id = ?",
        ].join(" "),
      ).bind(deviceId, accountId),
    ]);
  }
  if (accountId && deviceId && status === "reauthentication_required") {
    await env.DB.batch([
      env.DB.prepare(
        [
          "UPDATE devices SET status = 'needs_renewal', last_health_status = 'needs_renewal',",
          "last_health_message = ?, last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
          "WHERE id = ? AND account_id = ?",
        ].join(" "),
      ).bind(message || "Apple Find My login needs renewal.", deviceId, accountId),
      env.DB.prepare(
        [
          "INSERT INTO notification_events (id, account_id, device_id, kind, title, body)",
          "SELECT ?, ?, ?, 'renewal_required', ?, ?",
          "WHERE NOT EXISTS (SELECT 1 FROM notification_events WHERE account_id = ? AND device_id = ?",
          "AND kind = 'renewal_required' AND delivery_status IN ('queued', 'push_sent', 'email_sent'))",
        ].join(" "),
      ).bind(
        crypto.randomUUID(),
        accountId,
        deviceId,
        "Renew Apple login",
        "Apple Find My needs a fresh login before Alexa can ring this device.",
        accountId,
        deviceId,
      ),
    ]);
    ctx.waitUntil(deliverQueuedNotifications(env, accountId));
  }
  return json({ ok: true });
}

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (request.method === "GET" && path === "/api/config") {
    return json({
      appName: env.APP_NAME,
      auth0Domain: authConfigured(env) ? env.AUTH0_DOMAIN : "",
      auth0ClientId: authConfigured(env) ? env.AUTH0_CLIENT_ID : "",
      auth0Audience: authConfigured(env) ? env.AUTH0_AUDIENCE : "",
      auth0Connection: authConfigured(env) ? env.AUTH0_CONNECTION : "",
      publicBaseUrl: env.PUBLIC_BASE_URL,
      vapidPublicKey: env.VAPID_PUBLIC_KEY || "",
      emailFallbackAvailable: Boolean(env.EMAIL && env.EMAIL_FROM),
    });
  }
  if (request.method === "GET" && path === "/api/owner/status") return handleOwnerStatus(request, env);
  if (request.method === "POST" && path === "/api/owner/push-subscriptions") {
    return handleOwnerPushSubscription(request, env);
  }
  if (request.method === "GET" && path === "/api/runner/jobs") return handleRunnerJobs(request, env);
  if (request.method === "POST" && path === "/api/runner/events") return handleRunnerEvent(request, env, ctx);
  if (request.method === "GET" && path.startsWith("/api/runner/setup/")) {
    if (!runnerAuthorized(request, env)) throw new HttpError(403, "Runner token is invalid.");
    const setupId = decodeURIComponent(path.slice("/api/runner/setup/".length));
    const setup = await env.DB.prepare(
      [
        "SELECT id, status, verification_code, device_candidates_json, selected_candidate_id, selected_devices_json,",
        "confirmed_test_ring, verification_method FROM setup_sessions WHERE id = ?",
      ].join(" "),
    )
      .bind(setupId)
      .first();
    if (!setup) throw new HttpError(404, "Setup session not found.");
    return json(setup);
  }

  if (path.startsWith("/api/")) {
    const account = await requireAccount(request, env);
    if (request.method === "GET" && path === "/api/me") return json(await statusPayload(env, account));
    if (request.method === "GET" && path === "/api/status") return json(await statusPayload(env, account));
    if (request.method === "POST" && path === "/api/setup/start") return handleSetupStart(request, env, account);
    if (request.method === "GET" && path.startsWith("/api/setup/")) {
      return handleSetupStatus(env, account, decodeURIComponent(path.slice("/api/setup/".length)));
    }
    if (request.method === "POST" && path.startsWith("/api/setup/")) {
      return handleSetupUpdate(request, env, account, decodeURIComponent(path.slice("/api/setup/".length)));
    }
    if (request.method === "POST" && path.startsWith("/api/devices/") && path.endsWith("/label")) {
      const deviceId = decodeURIComponent(path.slice("/api/devices/".length, -"/label".length));
      return handleDeviceRename(request, env, account, deviceId);
    }
    if (request.method === "POST" && path === "/api/ring/request") return handleRingRequest(request, env, account, "web");
    if (request.method === "POST" && path === "/api/push-subscriptions") return handlePushSubscription(request, env, account);
    if (request.method === "POST" && path === "/api/push-subscriptions/revoke") {
      return handlePushUnsubscribe(request, env, account);
    }
    if (path === "/api/admin/summary" && request.method === "GET") {
      await requireOwner(request, env);
      return handleAdminSummary(env);
    }
    if (path === "/api/admin/accounts" && request.method === "GET") {
      await requireOwner(request, env);
      return handleAdminAccounts(env);
    }
    if (path === "/api/admin/invites" && request.method === "GET") {
      await requireOwner(request, env);
      return handleAdminInvites(env);
    }
    if (path === "/api/admin/invites" && request.method === "POST") {
      const owner = await requireOwner(request, env);
      return handleCreateInvite(request, env, owner);
    }
    throw new HttpError(404, "API route not found.");
  }
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const shared = crossOriginPath(new URL(request.url).pathname);
    if (shared && request.method === "OPTIONS") return withCors(new Response(null, { status: 204 }));
    try {
      const response = await route(request, env, ctx);
      return shared ? withCors(response) : response;
    } catch (error) {
      const failure = error instanceof HttpError
        ? json({ error: error.message }, error.status)
        : (console.error(error), json({ error: "Unexpected server error." }, 500));
      return shared ? withCors(failure) : failure;
    }
  },
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(enqueueDailyHealthChecks(env));
    ctx.waitUntil(deliverQueuedNotifications(env));
  },
} satisfies ExportedHandler<Env>;
