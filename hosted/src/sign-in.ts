// Sign-in owned by this app, running alongside Auth0 for the migration window.
//
// Nothing here switches anything off. requireAccount tries a session issued
// here first and falls back to Auth0, so an account can arrive by either route
// and a mistake in this file cannot lock anyone out.

export const SESSION_COOKIE = "df_session";
const SESSION_DAYS = 90;
const TOKEN_HOURS = 48;

// The most Workers allows: above this the runtime throws
// "Pbkdf2 failed: iteration counts above 100000 are not supported". That is
// well under OWASP's 600,000 for PBKDF2-SHA-256, so the shortfall is covered by
// peppering below rather than pretended away. Recorded in the hash itself so
// the cost can be raised if the platform ever lifts the cap.
const PBKDF2_ITERATIONS = 100_000;

// A stolen database is not enough to attack these hashes: the password is first
// HMAC'd with a key held as a Worker secret, which Cloudflare will not hand
// back through its API. Domain-separated from the settings encryption so the
// two uses of SETTINGS_KEY cannot interfere.
const PEPPER_LABEL = "device-finder/password-pepper/v1";

const encoder = new TextEncoder();

const hex = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const randomHex = (bytes: number): string =>
  hex(crypto.getRandomValues(new Uint8Array(new ArrayBuffer(bytes))).buffer);

export async function sha256Hex(value: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

/** Constant-time compare, so a wrong password cannot be narrowed by timing. */
function equals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return difference === 0;
}

async function derive(password: string, saltHex: string, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: hexToBytes(saltHex), iterations },
    key,
    256,
  );
  return hex(bits);
}

function hexToBytes(value: string): Uint8Array<ArrayBuffer> {
  const pairs = value.match(/.{1,2}/g) ?? [];
  const bytes = new Uint8Array(new ArrayBuffer(pairs.length));
  pairs.forEach((pair, index) => { bytes[index] = Number.parseInt(pair, 16); });
  return bytes;
}

async function peppered(env: Env, password: string): Promise<string> {
  const secret = (env as Env & { SETTINGS_KEY?: string }).SETTINGS_KEY?.trim();
  if (!secret) return password;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(`${PEPPER_LABEL}:${secret}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return hex(await crypto.subtle.sign("HMAC", key, encoder.encode(password)));
}

export async function hashPassword(env: Env, password: string): Promise<string> {
  const salt = randomHex(16);
  // The scheme name records that a pepper was applied, so a hash written while
  // the secret was present is never checked as though it were not.
  const digest = await derive(await peppered(env, password), salt, PBKDF2_ITERATIONS);
  return `pbkdf2p$sha256$${PBKDF2_ITERATIONS}$${salt}$${digest}`;
}

export async function verifyPassword(env: Env, password: string, stored: string): Promise<boolean> {
  const [scheme, hash, iterations, salt, digest] = stored.split("$");
  if ((scheme !== "pbkdf2" && scheme !== "pbkdf2p") || hash !== "sha256" || !salt || !digest) return false;
  const count = Number(iterations);
  if (!Number.isInteger(count) || count <= 0 || count > PBKDF2_ITERATIONS) return false;
  const input = scheme === "pbkdf2p" ? await peppered(env, password) : password;
  return equals(await derive(input, salt, count), digest);
}

export function cookieValue(header: string | null, name: string): string {
  for (const part of (header ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return "";
}

export function sessionCookie(value: string, maxAgeSeconds: number): string {
  // Lax rather than Strict: the Alexa and Apple flows return to this app from
  // elsewhere, and a Strict cookie would not be sent on that first navigation.
  return [
    `${SESSION_COOKIE}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ].join("; ");
}

export type SessionRecord = { account_id: string };

/** Resolves the account behind a session cookie, or null. Expiry is enforced here. */
export async function accountIdFromSession(request: Request, env: Env): Promise<string | null> {
  const raw = cookieValue(request.headers.get("cookie"), SESSION_COOKIE);
  if (!raw) return null;
  const row = await env.DB.prepare(
    "SELECT account_id FROM account_sessions WHERE id = ? AND datetime(expires_at) > CURRENT_TIMESTAMP",
  )
    .bind(await sha256Hex(raw))
    .first<SessionRecord>();
  return row?.account_id ?? null;
}

export async function createSession(env: Env, accountId: string, userAgent: string): Promise<string> {
  const value = randomHex(32);
  const expires = new Date(Date.now() + SESSION_DAYS * 86_400_000).toISOString();
  await env.DB.prepare(
    "INSERT INTO account_sessions (id, account_id, user_agent, expires_at) VALUES (?, ?, ?, ?)",
  )
    .bind(await sha256Hex(value), accountId, userAgent.slice(0, 300), expires)
    .run();
  return value;
}

export async function destroySession(request: Request, env: Env): Promise<void> {
  const raw = cookieValue(request.headers.get("cookie"), SESSION_COOKIE);
  if (!raw) return;
  await env.DB.prepare("DELETE FROM account_sessions WHERE id = ?").bind(await sha256Hex(raw)).run();
}

export const SESSION_MAX_AGE = SESSION_DAYS * 86_400;

/** Creates a single-use link token. Returns the value to email; only its hash is stored. */
export async function createPasswordToken(
  env: Env,
  accountId: string,
  purpose: "set" | "reset",
): Promise<string> {
  const value = randomHex(32);
  const expires = new Date(Date.now() + TOKEN_HOURS * 3_600_000).toISOString();
  await env.DB.batch([
    // One live link per account: issuing a new one retires any earlier link, so
    // a forwarded or resent email cannot be replayed later.
    env.DB.prepare(
      "UPDATE password_tokens SET used_at = CURRENT_TIMESTAMP WHERE account_id = ? AND used_at IS NULL",
    ).bind(accountId),
    env.DB.prepare(
      "INSERT INTO password_tokens (id, account_id, purpose, expires_at) VALUES (?, ?, ?, ?)",
    ).bind(await sha256Hex(value), accountId, purpose, expires),
  ]);
  return value;
}

export async function redeemPasswordToken(env: Env, value: string): Promise<string | null> {
  const id = await sha256Hex(value);
  const row = await env.DB.prepare(
    [
      "SELECT account_id FROM password_tokens",
      "WHERE id = ? AND used_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP",
    ].join(" "),
  )
    .bind(id)
    .first<SessionRecord>();
  if (!row) return null;
  const spent = await env.DB.prepare(
    "UPDATE password_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL",
  )
    .bind(id)
    .run();
  // If the update changed nothing, another request redeemed it first.
  return spent.meta.changes ? row.account_id : null;
}

export const TOKEN_VALID_HOURS = TOKEN_HOURS;
