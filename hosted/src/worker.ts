import { createRemoteJWKSet, jwtVerify } from "jose";
import webpush from "web-push";
import { WorkerMailer } from "worker-mailer";
import {
  OAUTH_KEYS,
  accountIdFromAccessToken,
  clientCredentials,
  issueCode,
  issueTokens,
  parseClient,
  randomToken,
  redeemCode,
  redirectAllowed,
  revokeAccountTokens,
  rotateRefreshToken,
  safeEquals,
} from "./oauth";
import {
  SESSION_MAX_AGE,
  TOKEN_VALID_HOURS,
  accountIdFromSession,
  createPasswordToken,
  createSession,
  destroySession,
  hashPassword,
  redeemPasswordToken,
  sessionCookie,
  verifyPassword,
} from "./sign-in";

type Identity = { subject: string; accessToken: string; email?: string; displayName?: string };
type Account = {
  id: string;
  authSubject: string;
  email: string;
  displayName: string;
  role: "owner" | "user";
  status: "active" | "suspended";
  storeApplePassword: boolean;
};
type AccountRow = {
  id: string;
  auth_subject: string;
  email: string;
  display_name: string;
  role: "owner" | "user";
  status: "active" | "suspended";
  store_apple_password: number;
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
  "access-control-allow-methods": "GET, POST, PUT, OPTIONS",
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
    storeApplePassword: Boolean(row.store_apple_password),
  };
}

const ACCOUNT_COLUMNS = "id, auth_subject, email, display_name, role, status, store_apple_password";

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
    `SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE auth_subject = ?`,
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
  return {
    id: accountId,
    authSubject: identity.subject,
    email: profile.email,
    displayName: profile.displayName,
    role,
    status: "active",
    storeApplePassword: false,
  };
}

async function accountById(env: Env, accountId: string): Promise<Account | null> {
  const row = await env.DB.prepare(`SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE id = ?`)
    .bind(accountId)
    .first<AccountRow>();
  return row ? mapAccount(row) : null;
}

async function requireAccount(request: Request, env: Env): Promise<Account> {
  // A session issued by this app is tried first because it is the route being
  // migrated to. Auth0 stays accepted for the whole migration window, so an
  // account can arrive by either and no one is ever locked out mid-change.
  const sessionAccountId = await accountIdFromSession(request, env);
  if (sessionAccountId) {
    const account = await accountById(env, sessionAccountId);
    if (account) {
      if (account.status !== "active") throw new HttpError(403, "This account is suspended.");
      return account;
    }
  }

  // An access token this app issued to the Alexa skill. Checked before Auth0
  // because both arrive as a bearer token and only one of them is a JWT.
  const bearer = request.headers.get("authorization");
  if (bearer?.startsWith("Bearer ")) {
    const tokenAccountId = await accountIdFromAccessToken(env, bearer.slice(7));
    if (tokenAccountId) {
      const account = await accountById(env, tokenAccountId);
      if (account) {
        if (account.status !== "active") throw new HttpError(403, "This account is suspended.");
        return account;
      }
    }
  }

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
      // Tells the runner it may fall back to the stored Apple password after a
      // session expires. It never carries the password itself.
      storedApplePassword: account.storeApplePassword,
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
  storeApplePassword = false,
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
      storeApplePassword,
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
    // Opting in is per setup attempt and defaults to off, so an account only
    // holds a password because someone ticked the box on this screen.
    const storeApplePassword = payload.storeApplePassword === true;
    await env.DB.batch([
      env.DB.prepare(
        [
          "UPDATE setup_sessions SET status = 'awaiting_credentials', apple_account_email = ?,",
          "verification_method = ?, message = 'Starting Apple setup relay.',",
          "runner_started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        ].join(" "),
      ).bind(appleId, verificationMethod, setupId),
      env.DB.prepare("UPDATE accounts SET store_apple_password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(storeApplePassword ? 1 : 0, account.id),
    ]);
    await dispatchOrCloseSession(env, setupId, () =>
      dispatchSetupJob(
        env, setupId, runnerToken, account, session.device_id as string,
        appleId, password, verificationMethod, undefined, storeApplePassword,
      ),
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

    // Alexa sends this identifier on every request, linked or not, so recording
    // it now — while account linking still proves who the caller is — is what
    // lets the skill stop needing a token later without anyone re-pairing.
    const alexaUserId = stringField(payload, "alexaUserId", 500);
    if (alexaUserId) {
      const claimed = await env.DB.prepare(
        "SELECT account_id FROM alexa_links WHERE amazon_user_id = ?",
      )
        .bind(alexaUserId)
        .first<{ account_id: string }>();
      if (claimed && claimed.account_id !== account.id) {
        // The column is UNIQUE, so writing it anyway would fail the request and
        // lose the ring. Say what happened instead and carry on.
        console.error("Alexa household already bound to another Device Finder account");
      } else if (!claimed) {
        await env.DB.prepare(
          "UPDATE alexa_links SET amazon_user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE account_id = ?",
        )
          .bind(alexaUserId, account.id)
          .run();
      }
    }
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

type SmtpSettings = {
  host: string;
  port: number;
  username: string;
  password: string;
  from: string;
  fromName: string;
  secure: boolean;
};

const SMTP_KEYS = ["smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from", "smtp_from_name", "smtp_secure"] as const;

// The mail password has to live in the database to be settable from a panel,
// so it is encrypted with a key held as a Worker secret. Cloudflare will not
// hand a secret back through its API, so a D1 export reveals nothing on its
// own. It is not proof against someone who can deploy code — they could read
// the key — but it removes the passive-read exposure that plaintext has.
const SECRET_PREFIX = "v1.";

const bytesFromHex = (value: string): Uint8Array<ArrayBuffer> => {
  const pairs = value.match(/.{1,2}/g) ?? [];
  const bytes = new Uint8Array(new ArrayBuffer(pairs.length));
  pairs.forEach((pair, index) => { bytes[index] = Number.parseInt(pair, 16); });
  return bytes;
};

async function settingsKey(env: Env): Promise<CryptoKey | null> {
  const raw = (env as Env & { SETTINGS_KEY?: string }).SETTINGS_KEY?.trim();
  if (!raw) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptSecret(env: Env, value: string): Promise<string> {
  const key = await settingsKey(env);
  if (!key) throw new HttpError(503, "Set the SETTINGS_KEY secret before saving a mail password.");
  const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(12)));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return `${SECRET_PREFIX}${hex(iv.buffer)}.${hex(sealed)}`;
}

async function decryptSecret(env: Env, stored: string): Promise<string> {
  // Anything without the marker predates encryption and is read as-is, so an
  // existing configuration keeps working until it is next saved.
  if (!stored.startsWith(SECRET_PREFIX)) return stored;
  const key = await settingsKey(env);
  if (!key) return "";
  const [, ivHex, dataHex] = stored.split(".");
  if (!ivHex || !dataHex) return "";
  try {
    const opened = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytesFromHex(ivHex) },
      key,
      bytesFromHex(dataHex),
    );
    return new TextDecoder().decode(opened);
  } catch {
    console.error("Stored mail password could not be decrypted; SETTINGS_KEY may have changed");
    return "";
  }
}

async function readSettings(env: Env, keys: readonly string[]): Promise<Record<string, string>> {
  const placeholders = keys.map(() => "?").join(", ");
  const result = await env.DB.prepare(`SELECT key, value FROM app_settings WHERE key IN (${placeholders})`)
    .bind(...keys)
    .all<{ key: string; value: string }>();
  return Object.fromEntries(result.results.map((row) => [row.key, row.value]));
}

async function smtpSettings(env: Env): Promise<SmtpSettings | null> {
  const stored = await readSettings(env, SMTP_KEYS);
  const host = stored.smtp_host ?? "";
  const from = stored.smtp_from ?? "";
  const port = Number(stored.smtp_port ?? "");
  // Without a host, a sender and a usable port there is nothing to try, and a
  // half-configured server would fail once per queued alert.
  if (!host || !from || !Number.isInteger(port) || port <= 0) return null;
  return {
    host,
    port,
    username: stored.smtp_username ?? "",
    password: await decryptSecret(env, stored.smtp_password ?? ""),
    from,
    fromName: stored.smtp_from_name || "Device Finder",
    secure: stored.smtp_secure !== "0",
  };
}

const escapeHtml = (value: string): string =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

async function sendEmailViaSmtp(smtp: SmtpSettings, to: string, title: string, body: string): Promise<void> {
  // Port 25 is blocked outbound from Workers; 587 and 465 are the usable ones.
  const mailer = await WorkerMailer.connect({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.secure,
    ...(smtp.username ? { credentials: { username: smtp.username, password: smtp.password }, authType: "plain" as const } : {}),
  });
  try {
    await mailer.send({
      from: { name: smtp.fromName, email: smtp.from },
      to: { email: to },
      subject: title,
      text: body,
      html: `<p>${escapeHtml(body)}</p>`,
    });
  } finally {
    await mailer.close().catch(() => undefined);
  }
}

async function sendEmailNotification(env: Env, email: string, title: string, body: string): Promise<boolean> {
  const smtp = await smtpSettings(env);
  if (!smtp) return false;
  try {
    await sendEmailViaSmtp(smtp, email, title, body);
    return true;
  } catch (error) {
    console.error("SMTP delivery failed", error instanceof Error ? error.message : error);
    return false;
  }
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
      `SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE id = ? AND status = 'active'`,
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

async function ownerAccount(request: Request, env: Env): Promise<Account> {
  if (!myBuildsAuthorized(request, env)) throw new HttpError(403, "Status token is invalid.");
  const owner = await env.DB.prepare(
    `SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE email_normalized = ? AND role = 'owner'`,
  )
    .bind(normalizeEmail(env.OWNER_EMAIL))
    .first<AccountRow>();
  if (!owner) throw new HttpError(409, "Open Device Finder and sign in once before enabling owner alerts.");
  return mapAccount(owner);
}

async function handleOwnerPushSubscription(request: Request, env: Env): Promise<Response> {
  return handlePushSubscription(request, env, await ownerAccount(request, env));
}

async function handleOwnerPushUnsubscribe(request: Request, env: Env): Promise<Response> {
  return handlePushUnsubscribe(request, env, await ownerAccount(request, env));
}

// A hash of a throwaway password, used to spend the same work on an unknown
// address as on a real one. Without it, a fast rejection says "no account here".
const ABSENT_ACCOUNT_HASH =
  "pbkdf2p$sha256$100000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000";

function signedInResponse(value: string, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { ...jsonHeaders, "set-cookie": sessionCookie(value, SESSION_MAX_AGE) },
  });
}

async function handleSignIn(request: Request, env: Env): Promise<Response> {
  const payload = await readJson(request);
  const email = normalizeEmail(stringField(payload, "email", 320));
  const password = stringField(payload, "password", 500);
  if (!email || !password) throw new HttpError(400, "Email and password are required.");

  const row = await env.DB.prepare(
    [
      "SELECT a.id, c.password_hash FROM accounts a",
      "JOIN account_credentials c ON c.account_id = a.id",
      "WHERE a.email_normalized = ? AND a.status = 'active'",
    ].join(" "),
  )
    .bind(email)
    .first<{ id: string; password_hash: string }>();

  const matched = await verifyPassword(env, password, row?.password_hash ?? ABSENT_ACCOUNT_HASH);
  // One answer for both failures: whether an address has an account is not
  // something an unauthenticated caller gets to learn.
  if (!row || !matched) throw new HttpError(401, "That email and password do not match.");

  const value = await createSession(env, row.id, request.headers.get("user-agent") ?? "");
  return signedInResponse(value, { status: "signed_in" });
}

async function handleSignOut(request: Request, env: Env): Promise<Response> {
  await destroySession(request, env);
  return new Response(JSON.stringify({ status: "signed_out" }), {
    status: 200,
    headers: { ...jsonHeaders, "set-cookie": sessionCookie("", 0) },
  });
}

async function sendPasswordLink(
  env: Env,
  account: { id: string; email: string; display_name: string },
  purpose: "set" | "reset",
): Promise<void> {
  const smtp = await smtpSettings(env);
  if (!smtp) {
    console.error("Password link not sent: no mail server is configured");
    return;
  }
  const token = await createPasswordToken(env, account.id, purpose);
  const link = `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/?set-password=${encodeURIComponent(token)}`;
  const greeting = account.display_name ? `Hi ${account.display_name},` : "Hi,";
  const opening = purpose === "set"
    ? "Device Finder has its own sign-in now, so it needs a password of its own."
    : "You asked to reset your Device Finder password.";
  try {
    await sendEmailViaSmtp(
      smtp,
      account.email,
      purpose === "set" ? "Set your Device Finder password" : "Reset your Device Finder password",
      [
        greeting,
        "",
        opening,
        "",
        `Choose one here: ${link}`,
        "",
        `The link works once and expires in ${TOKEN_VALID_HOURS} hours.`,
        "If you did not expect this, you can ignore it — nothing changes until the link is used.",
      ].join("\n"),
    );
  } catch (error) {
    console.error("Password link delivery failed", error instanceof Error ? error.message : error);
  }
}

async function handlePasswordRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const payload = await readJson(request);
  const email = normalizeEmail(stringField(payload, "email", 320));
  if (email) {
    const account = await env.DB.prepare(
      "SELECT id, email, display_name FROM accounts WHERE email_normalized = ? AND status = 'active'",
    )
      .bind(email)
      .first<{ id: string; email: string; display_name: string }>();
    if (account) ctx.waitUntil(sendPasswordLink(env, account, "reset"));
  }
  // Same answer either way, for the same reason as sign-in.
  return json({ status: "sent" });
}

async function handlePasswordSet(request: Request, env: Env): Promise<Response> {
  const payload = await readJson(request);
  const token = stringField(payload, "token", 200);
  const password = stringField(payload, "password", 500);
  if (password.length < 10) throw new HttpError(400, "Use a password of at least 10 characters.");

  const accountId = await redeemPasswordToken(env, token);
  if (!accountId) {
    throw new HttpError(400, "That link has expired or was already used. Ask for a new one.");
  }

  const hash = await hashPassword(env, password);
  await env.DB.batch([
    env.DB.prepare(
      [
        "INSERT INTO account_credentials (account_id, password_hash) VALUES (?, ?)",
        "ON CONFLICT(account_id) DO UPDATE SET password_hash = excluded.password_hash,",
        "updated_at = CURRENT_TIMESTAMP",
      ].join(" "),
    ).bind(accountId, hash),
    // Anyone signed in elsewhere is signed out: a password change is how
    // someone takes their account back.
    env.DB.prepare("DELETE FROM account_sessions WHERE account_id = ?").bind(accountId),
  ]);

  const value = await createSession(env, accountId, request.headers.get("user-agent") ?? "");
  return signedInResponse(value, { status: "password_set" });
}

function oauthPage(title: string, body: string): Response {
  return new Response(
    [
      '<!doctype html><html lang="en"><head><meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      `<title>${escapeText(title)}</title>`,
      '<style>',
      ':root{color-scheme:light dark}',
      'body{font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;',
      'display:grid;place-items:center;min-height:100vh;background:#f3f5f7;color:#16202b}',
      '@media(prefers-color-scheme:dark){body{background:#0e1620;color:#dde5eb}',
      '.card{background:#16212c!important;border-color:#2a3845!important}',
      'input{background:#0e1620!important;color:inherit!important;border-color:#2a3845!important}}',
      '.card{background:#fff;border:1px solid #cfd7de;border-radius:10px;padding:28px;max-width:26rem;width:calc(100% - 2rem)}',
      'h1{font-size:1.3rem;margin:0 0 .5rem;letter-spacing:-.01em}',
      'p{margin:0 0 1rem;color:#55646f}',
      '@media(prefers-color-scheme:dark){p{color:#8b9ba8}}',
      'label{display:grid;gap:.3rem;margin-bottom:.85rem;font-size:.82rem;text-transform:uppercase;letter-spacing:.05em}',
      'input{font:inherit;padding:.6rem .7rem;border:1px solid #cfd7de;border-radius:6px;text-transform:none}',
      'button{font:600 15px inherit;padding:.7rem 1.1rem;border:0;border-radius:6px;background:#2f6f82;color:#fff;cursor:pointer;width:100%}',
      '.err{color:#a83a28}',
      '</style></head><body><main class="card">',
      body,
      '</main></body></html>',
    ].join(""),
    { status: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } },
  );
}

const escapeText = (value: string): string =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

function hiddenFields(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([key, value]) => `<input type="hidden" name="${escapeText(key)}" value="${escapeText(value)}">`)
    .join("");
}

type AuthorizeParams = {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  responseType: string;
  challengeMethod: string;
};

function readAuthorizeParams(source: URLSearchParams): AuthorizeParams {
  return {
    clientId: source.get("client_id") ?? "",
    redirectUri: source.get("redirect_uri") ?? "",
    state: source.get("state") ?? "",
    codeChallenge: source.get("code_challenge") ?? "",
    responseType: source.get("response_type") ?? "",
    challengeMethod: source.get("code_challenge_method") ?? "",
  };
}

function authorizeRedirect(redirectUri: string, params: Record<string, string>): Response {
  const target = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) if (value) target.searchParams.set(key, value);
  return new Response(null, { status: 302, headers: { location: target.toString(), "cache-control": "no-store" } });
}

async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const form = request.method === "POST" ? new URLSearchParams(await request.text()) : url.searchParams;
  const params = readAuthorizeParams(form);

  const client = parseClient(await readSettings(env, OAUTH_KEYS));
  if (!client) {
    return oauthPage("Not set up", "<h1>Alexa linking is not set up yet.</h1><p>Generate client credentials in the owner panel first.</p>");
  }
  // A bad client or redirect must never be redirected back to — the URI is not
  // trusted yet, so the error stays here.
  if (!safeEquals(params.clientId, client.clientId) || !redirectAllowed(client, params.redirectUri)) {
    return oauthPage("Cannot continue", '<h1>That link is not valid.</h1><p class="err">The client or redirect address does not match what is registered.</p>');
  }
  if (params.responseType !== "code") {
    return authorizeRedirect(params.redirectUri, { error: "unsupported_response_type", state: params.state });
  }
  // PKCE is required rather than optional: without it an intercepted code is
  // enough on its own.
  if (params.challengeMethod !== "S256" || !params.codeChallenge) {
    return authorizeRedirect(params.redirectUri, { error: "invalid_request", state: params.state });
  }

  const carried = {
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    state: params.state,
    code_challenge: params.codeChallenge,
    code_challenge_method: params.challengeMethod,
    response_type: params.responseType,
  };

  let accountId = await accountIdFromSession(request, env);
  let signInError = "";

  if (request.method === "POST" && !accountId) {
    const email = normalizeEmail(form.get("email") ?? "");
    const password = form.get("password") ?? "";
    if (email && password) {
      const row = await env.DB.prepare(
        [
          "SELECT a.id, c.password_hash FROM accounts a",
          "JOIN account_credentials c ON c.account_id = a.id",
          "WHERE a.email_normalized = ? AND a.status = 'active'",
        ].join(" "),
      )
        .bind(email)
        .first<{ id: string; password_hash: string }>();
      const matched = await verifyPassword(env, password, row?.password_hash ?? ABSENT_ACCOUNT_HASH);
      if (row && matched) {
        const value = await createSession(env, row.id, request.headers.get("user-agent") ?? "");
        // Signed in, but not linked yet: the person still has to press Connect,
        // so signing in can never by itself hand an account to an Echo.
        return new Response(
          [
            '<!doctype html><meta charset="utf-8"><form id="f" method="post" action="/oauth/authorize">',
            hiddenFields(carried),
            '</form><script>document.getElementById("f").submit()</script>',
          ].join(""),
          {
            status: 200,
            headers: {
              "content-type": "text/html; charset=utf-8",
              "cache-control": "no-store",
              "set-cookie": sessionCookie(value, SESSION_MAX_AGE),
            },
          },
        );
      }
      signInError = "That email and password do not match.";
    }
  }

  if (!accountId) {
    return oauthPage(
      "Sign in",
      [
        "<h1>Sign in to connect Alexa.</h1>",
        "<p>Use your Device Finder email and password.</p>",
        signInError ? `<p class="err">${escapeText(signInError)}</p>` : "",
        '<form method="post" action="/oauth/authorize">',
        hiddenFields(carried),
        '<label>Email<input name="email" type="email" autocomplete="username" required></label>',
        '<label>Password<input name="password" type="password" autocomplete="current-password" required></label>',
        '<button type="submit">Sign in</button>',
        "</form>",
      ].join(""),
    );
  }

  if (request.method === "POST" && form.get("approve") === "yes") {
    // A cross-site POST never arrives with the session cookie, because it is
    // SameSite=Lax, so reaching here means the person is really on this page.
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(env.PUBLIC_BASE_URL).origin) {
      return oauthPage("Cannot continue", '<h1>That request did not come from here.</h1>');
    }
    const code = await issueCode(env, accountId, client, params.redirectUri, params.codeChallenge);
    return authorizeRedirect(params.redirectUri, { code, state: params.state });
  }

  const account = await accountById(env, accountId);
  return oauthPage(
    "Connect Alexa",
    [
      "<h1>Connect Alexa to Device Finder?</h1>",
      `<p>Alexa will be able to ring the Apple devices on ${escapeText(account?.email ?? "your account")}.</p>`,
      '<form method="post" action="/oauth/authorize">',
      hiddenFields({ ...carried, approve: "yes" }),
      '<button type="submit">Connect</button>',
      "</form>",
    ].join(""),
  );
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  const form = new URLSearchParams(await request.text());
  const client = parseClient(await readSettings(env, OAUTH_KEYS));
  const supplied = clientCredentials(request, form);

  const tokenError = (error: string, status = 400): Response =>
    new Response(JSON.stringify({ error }), { status, headers: jsonHeaders });

  if (!client || !safeEquals(supplied.clientId, client.clientId)) return tokenError("invalid_client", 401);
  if (!safeEquals(await sha256Hex(supplied.clientSecret), client.secretHash)) {
    return tokenError("invalid_client", 401);
  }

  const grantType = form.get("grant_type") ?? "";

  if (grantType === "authorization_code") {
    const accountId = await redeemCode(
      env,
      form.get("code") ?? "",
      client,
      form.get("redirect_uri") ?? "",
      form.get("code_verifier") ?? "",
    );
    if (!accountId) return tokenError("invalid_grant");
    const issued = await issueTokens(env, accountId, client.clientId);
    // A link only counts once Alexa has really completed it.
    await env.DB.prepare(
      [
        "UPDATE alexa_links SET status = 'linked', linked_at = COALESCE(linked_at, CURRENT_TIMESTAMP),",
        "updated_at = CURRENT_TIMESTAMP WHERE account_id = ?",
      ].join(" "),
    )
      .bind(accountId)
      .run();
    return new Response(
      JSON.stringify({
        access_token: issued.accessToken,
        refresh_token: issued.refreshToken,
        token_type: "Bearer",
        expires_in: issued.expiresIn,
      }),
      { status: 200, headers: jsonHeaders },
    );
  }

  if (grantType === "refresh_token") {
    const issued = await rotateRefreshToken(env, form.get("refresh_token") ?? "", client.clientId);
    if (!issued) return tokenError("invalid_grant");
    return new Response(
      JSON.stringify({
        access_token: issued.accessToken,
        refresh_token: issued.refreshToken,
        token_type: "Bearer",
        expires_in: issued.expiresIn,
      }),
      { status: 200, headers: jsonHeaders },
    );
  }

  return tokenError("unsupported_grant_type");
}

async function writeSettings(env: Env, entries: Record<string, string>): Promise<void> {
  const statements = Object.entries(entries).map(([key, value]) =>
    env.DB.prepare(
      [
        "INSERT INTO app_settings (key, value) VALUES (?, ?)",
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
      ].join(" "),
    ).bind(key, value),
  );
  if (statements.length) await env.DB.batch(statements);
}

async function handleOwnerEmailSettings(request: Request, env: Env): Promise<Response> {
  if (!myBuildsAuthorized(request, env)) throw new HttpError(403, "Status token is invalid.");

  if (request.method === "GET") {
    const stored = await readSettings(env, SMTP_KEYS);
    return json({
      host: stored.smtp_host ?? "",
      port: stored.smtp_port ?? "",
      username: stored.smtp_username ?? "",
      from: stored.smtp_from ?? "",
      fromName: stored.smtp_from_name ?? "",
      secure: stored.smtp_secure !== "0",
      // Reports only that a password is on file. The value is never returned.
      passwordSet: Boolean(stored.smtp_password),
    });
  }

  const payload = await readJson(request);
  const host = stringField(payload, "host", 255);
  const from = stringField(payload, "from", 320);
  // A JSON number is as valid here as a typed string, and stringField discards
  // anything that is not a string — which rejected every port the form sent.
  const port = typeof payload.port === "number"
    ? payload.port
    : Number(stringField(payload, "port", 6));
  if (!host) throw new HttpError(400, "A mail server host is required.");
  if (!from.includes("@")) throw new HttpError(400, "A valid sender address is required.");
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new HttpError(400, "A valid port is required. Use 587 or 465.");
  }
  if (port === 25) {
    throw new HttpError(400, "Cloudflare blocks outbound port 25. Use 587 or 465 instead.");
  }

  const entries: Record<string, string> = {
    smtp_host: host,
    smtp_port: String(port),
    smtp_username: stringField(payload, "username", 320),
    smtp_from: from,
    smtp_from_name: stringField(payload, "fromName", 80),
    smtp_secure: payload.secure === false ? "0" : "1",
  };
  // An empty password means "leave the stored one alone", so re-saving the
  // form without retyping it does not wipe a working configuration.
  const password = stringField(payload, "password", 500);
  if (password) entries.smtp_password = await encryptSecret(env, password);

  await writeSettings(env, entries);
  return json({ status: "saved", passwordSet: Boolean(password) || Boolean((await readSettings(env, ["smtp_password"])).smtp_password) });
}

async function handleOwnerAlexaOauth(request: Request, env: Env): Promise<Response> {
  if (!myBuildsAuthorized(request, env)) throw new HttpError(403, "Status token is invalid.");
  const base = env.PUBLIC_BASE_URL.replace(/\/$/, "");

  if (request.method === "GET") {
    const client = parseClient(await readSettings(env, OAUTH_KEYS));
    return json({
      clientId: client?.clientId ?? "",
      // Reports only that a secret exists. It is shown once, when generated.
      secretSet: Boolean(client?.secretHash),
      redirectUris: client?.redirectUris ?? [],
      authorizationUrl: `${base}/oauth/authorize`,
      accessTokenUrl: `${base}/oauth/token`,
    });
  }

  if (request.method === "POST") {
    // Regenerating invalidates every existing Alexa link, because the tokens
    // were issued to the old client. Say so rather than letting it surprise.
    const clientId = `device-finder-${randomToken(8)}`;
    const secret = randomToken(32);
    await writeSettings(env, {
      oauth_client_id: clientId,
      oauth_client_secret_hash: await sha256Hex(secret),
    });
    return json({
      clientId,
      // The only time this is ever returned. It is stored hashed.
      clientSecret: secret,
      authorizationUrl: `${base}/oauth/authorize`,
      accessTokenUrl: `${base}/oauth/token`,
    });
  }

  const payload = await readJson(request);
  const raw = Array.isArray(payload.redirectUris) ? payload.redirectUris : [];
  const redirectUris = raw
    .filter((value): value is string => typeof value === "string")
    .map((value) => value.trim())
    .filter(Boolean)
    .slice(0, 10);
  if (redirectUris.some((value) => !value.startsWith("https://"))) {
    throw new HttpError(400, "Every redirect address must be https.");
  }
  await writeSettings(env, { oauth_redirect_uris: JSON.stringify(redirectUris) });
  return json({ redirectUris });
}

async function handleOwnerEmailTest(request: Request, env: Env): Promise<Response> {
  if (!myBuildsAuthorized(request, env)) throw new HttpError(403, "Status token is invalid.");
  const smtp = await smtpSettings(env);
  if (!smtp) throw new HttpError(409, "Save a host, port and sender address before sending a test.");

  const payload = await readJson(request).catch(() => ({}) as Record<string, unknown>);
  const to = stringField(payload, "to", 320) || env.OWNER_EMAIL;
  if (!to.includes("@")) throw new HttpError(400, "A valid recipient address is required.");

  try {
    await sendEmailViaSmtp(
      smtp,
      to,
      "Device Finder test email",
      "SMTP is set up correctly. Renewal alerts will reach you here when push cannot.",
    );
  } catch (error) {
    // The mail server's own words are the whole point of a test button.
    throw new HttpError(502, `The mail server rejected it: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  return json({ status: "sent", to });
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
  // The runner reports several sanitized failure categories and can gain more.
  // Anything that is not a known success or progress report counts as a
  // failure, so an unrecognised category can never leave a job queued forever
  // while the dashboard keeps showing the device as healthy.
  const runnerSucceeded = ["succeeded", "healthy"].includes(status);
  const runnerFailed = Boolean(status) && !runnerSucceeded && status !== "running";
  if (jobId && status) {
    const jobStatus = runnerSucceeded ? "succeeded" : runnerFailed ? "failed" : "running";
    await env.DB.prepare("UPDATE ring_jobs SET status = ?, message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(jobStatus, message || status, jobId)
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
      // Close any open alert for this device. Without this the dedupe guard
      // below would suppress the next genuine alert forever.
      env.DB.prepare(
        [
          "UPDATE notification_events SET delivery_status = 'dismissed'",
          "WHERE account_id = ? AND device_id = ? AND kind IN ('renewal_required', 'ring_failed')",
          "AND delivery_status IN ('queued', 'push_sent', 'email_sent')",
        ].join(" "),
      ).bind(accountId, deviceId),
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
  // Every other failure category, including ones this Worker does not know
  // about yet. Renewal is handled above because it has its own remedy.
  if (accountId && deviceId && runnerFailed && status !== "reauthentication_required") {
    await env.DB.batch([
      env.DB.prepare(
        [
          "UPDATE devices SET status = 'unhealthy', last_health_status = 'failed',",
          "last_health_message = ?, last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
          "WHERE id = ? AND account_id = ?",
        ].join(" "),
      ).bind(message || status, deviceId, accountId),
      env.DB.prepare(
        [
          "INSERT INTO notification_events (id, account_id, device_id, kind, title, body)",
          "SELECT ?, ?, ?, 'ring_failed', ?, ?",
          "WHERE NOT EXISTS (SELECT 1 FROM notification_events WHERE account_id = ? AND device_id = ?",
          "AND kind = 'ring_failed' AND delivery_status IN ('queued', 'push_sent', 'email_sent'))",
        ].join(" "),
      ).bind(
        crypto.randomUUID(),
        accountId,
        deviceId,
        "Device Finder needs attention",
        "Find My could not reach this Apple device. Open Device Finder to check its setup.",
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
  if (path === "/oauth/authorize" && (request.method === "GET" || request.method === "POST")) {
    return handleAuthorize(request, env);
  }
  if (path === "/oauth/token" && request.method === "POST") return handleToken(request, env);

  if (request.method === "GET" && path === "/api/config") {
    return json({
      appName: env.APP_NAME,
      auth0Domain: authConfigured(env) ? env.AUTH0_DOMAIN : "",
      auth0ClientId: authConfigured(env) ? env.AUTH0_CLIENT_ID : "",
      auth0Audience: authConfigured(env) ? env.AUTH0_AUDIENCE : "",
      auth0Connection: authConfigured(env) ? env.AUTH0_CONNECTION : "",
      publicBaseUrl: env.PUBLIC_BASE_URL,
      vapidPublicKey: env.VAPID_PUBLIC_KEY || "",
      emailFallbackAvailable: Boolean(await smtpSettings(env)),
    });
  }
  if (request.method === "GET" && path === "/api/owner/status") return handleOwnerStatus(request, env);
  if (request.method === "POST" && path === "/api/owner/push-subscriptions") {
    return handleOwnerPushSubscription(request, env);
  }
  if (request.method === "POST" && path === "/api/owner/push-subscriptions/revoke") {
    return handleOwnerPushUnsubscribe(request, env);
  }
  if ((request.method === "GET" || request.method === "PUT") && path === "/api/owner/email") {
    return handleOwnerEmailSettings(request, env);
  }
  if (request.method === "POST" && path === "/api/owner/email/test") {
    return handleOwnerEmailTest(request, env);
  }
  if (["GET", "PUT", "POST"].includes(request.method) && path === "/api/owner/alexa-oauth") {
    return handleOwnerAlexaOauth(request, env);
  }
  // Sign-in owned by this app. Unauthenticated by nature, so these sit above
  // the block below that requires an account.
  if (request.method === "POST" && path === "/api/auth/sign-in") return handleSignIn(request, env);
  if (request.method === "POST" && path === "/api/auth/sign-out") return handleSignOut(request, env);
  if (request.method === "POST" && path === "/api/auth/password/request") {
    return handlePasswordRequest(request, env, ctx);
  }
  if (request.method === "POST" && path === "/api/auth/password/set") {
    return handlePasswordSet(request, env);
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
