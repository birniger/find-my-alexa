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
// two uses of the same secret cannot interfere.
const PEPPER_LABEL = "device-finder/password-pepper/v1";

// Every hash carries a fingerprint of the pepper that made it, in the clear.
// Domain-separated from the pepper itself so that publishing the fingerprint
// cannot help anyone check a guess at the secret behind it.
const PEPPER_ID_LABEL = "device-finder/password-pepper-id/v1";

/** The fingerprint of "no pepper at all". */
const UNPEPPERED_ID = "00000000";

type PepperEnv = Env & {
  SETTINGS_KEY?: string;
  PASSWORD_PEPPER?: string;
  PASSWORD_PEPPER_PREVIOUS?: string;
};

/**
 * Every secret this Worker could pepper with, best first.
 *
 * PASSWORD_PEPPER exists because SETTINGS_KEY does two unrelated jobs: it
 * encrypts the mail password *and* peppered every password here. Rotating it
 * for the first reason silently invalidated every hash written under it, which
 * locked the owner out of an app whose only other doors — the reset email and
 * the Auth0 fallback — were shut by the same change.
 *
 * SETTINGS_KEY stays last so hashes written before the split keep verifying
 * with nothing to migrate, and PASSWORD_PEPPER_PREVIOUS exists so the next
 * rotation is a rotation rather than a lockout: set it to the outgoing value,
 * and old hashes verify and quietly re-write themselves as people sign in.
 */
function peppers(env: Env): string[] {
  const source = env as PepperEnv;
  const found: string[] = [];
  for (const candidate of [source.PASSWORD_PEPPER, source.PASSWORD_PEPPER_PREVIOUS, source.SETTINGS_KEY]) {
    const value = candidate?.trim();
    if (value && !found.includes(value)) found.push(value);
  }
  return found;
}

/** The pepper new hashes are written with. */
const currentPepper = (env: Env): string => peppers(env)[0] ?? "";

async function pepperId(secret: string): Promise<string> {
  if (!secret) return UNPEPPERED_ID;
  return (await sha256Hex(`${PEPPER_ID_LABEL}:${secret}`)).slice(0, 8);
}

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

async function peppered(secret: string, password: string): Promise<string> {
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

/** A stored iteration count, or null if it is missing, absurd, or unusable. */
function workFactor(iterations: string | undefined): number | null {
  const count = Number(iterations);
  if (!Number.isInteger(count) || count <= 0 || count > PBKDF2_ITERATIONS) return null;
  return count;
}

export async function hashPassword(env: Env, password: string): Promise<string> {
  const secret = currentPepper(env);
  const salt = randomHex(16);
  // The scheme name records that a pepper was applied, so a hash written while
  // a secret was present is never checked as though it were not. The
  // fingerprint records *which* pepper, so that a hash the current secrets
  // cannot open is recognised as such instead of read as a wrong password.
  const digest = await derive(await peppered(secret, password), salt, PBKDF2_ITERATIONS);
  return `pbkdf2p2$sha256$${PBKDF2_ITERATIONS}$${await pepperId(secret)}$${salt}$${digest}`;
}

export async function verifyPassword(env: Env, password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");

  if (parts[0] === "pbkdf2p2") {
    const [, hash, iterations, id, salt, digest] = parts;
    if (hash !== "sha256" || !id || !salt || !digest) return false;
    const count = workFactor(iterations);
    if (!count) return false;
    // Exactly one derivation: the fingerprint says which secret to use, so a
    // wrong password costs what a right one does and no more. "" is a
    // candidate only because it fingerprints to UNPEPPERED_ID — rewriting the
    // id to claim that is not a way through, as the digest was still made from
    // the peppered input and will not match.
    for (const secret of [...peppers(env), ""]) {
      if ((await pepperId(secret)) !== id) continue;
      return equals(await derive(await peppered(secret, password), salt, count), digest);
    }
    // Said out loud. The silent version of this — a pepper the Worker no
    // longer holds, reported as "that email and password do not match" — is
    // what turned a secret rotation into a lockout nobody could diagnose.
    console.error(
      `Password hash was written under pepper ${id}, which this Worker does not hold.` +
        " Set PASSWORD_PEPPER_PREVIOUS to the previous value to accept it.",
    );
    return false;
  }

  const [scheme, hash, iterations, salt, digest] = parts;
  if ((scheme !== "pbkdf2" && scheme !== "pbkdf2p") || hash !== "sha256" || !salt || !digest) return false;
  const count = workFactor(iterations);
  if (!count) return false;
  if (scheme === "pbkdf2") return equals(await derive(password, salt, count), digest);

  // A peppered hash from before the fingerprint existed, so the only way to
  // tell which secret made it is to try them. A match re-writes the row
  // through needsRehash, so this path drains instead of costing a derivation
  // per secret forever. The empty fallback preserves how these were read when
  // no secret was configured at all.
  const candidates = peppers(env);
  for (const secret of candidates.length ? candidates : [""]) {
    if (equals(await derive(await peppered(secret, password), salt, count), digest)) return true;
  }
  return false;
}

/**
 * Whether a hash that just verified should be written again — because it
 * predates the fingerprint, or carries one that is no longer current. Cheap:
 * string comparison, no derivation.
 */
export async function needsRehash(env: Env, stored: string): Promise<boolean> {
  const [scheme, , , id] = stored.split("$");
  if (scheme !== "pbkdf2p2") return true;
  return id !== (await pepperId(currentPepper(env)));
}

/**
 * A hash that cannot match, carrying the current fingerprint so that an
 * address with no account costs the same single derivation a real one does.
 * Without it, a fast rejection would say "no account here".
 */
export async function absentAccountHash(env: Env): Promise<string> {
  const id = await pepperId(currentPepper(env));
  return `pbkdf2p2$sha256$${PBKDF2_ITERATIONS}$${id}$${"0".repeat(32)}$${"0".repeat(64)}`;
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
