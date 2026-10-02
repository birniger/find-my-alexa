// An OAuth 2.0 authorization server scoped to one caller: the Alexa skill.
//
// This is the only part of leaving Auth0 where a mistake is an account
// takeover rather than a broken feature, so it supports as little as possible:
// one confidential client, exact-match redirect URIs, mandatory PKCE with
// S256, no scopes, no implicit grant, no dynamic registration. Anything not
// implemented cannot be got wrong.

import { sha256Hex } from "./sign-in.ts";

const CODE_TTL_SECONDS = 5 * 60;
const ACCESS_TTL_SECONDS = 24 * 60 * 60;
const REFRESH_TTL_SECONDS = 180 * 24 * 60 * 60;

export const OAUTH_KEYS = ["oauth_client_id", "oauth_client_secret_hash", "oauth_redirect_uris"] as const;

const hex = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

export const randomToken = (bytes = 32): string =>
  hex(crypto.getRandomValues(new Uint8Array(new ArrayBuffer(bytes))).buffer);

/** Constant-time compare so a wrong secret cannot be narrowed by timing. */
export function safeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return difference === 0;
}

export type OAuthClient = { clientId: string; secretHash: string; redirectUris: string[] };

export function parseClient(stored: Record<string, string>): OAuthClient | null {
  const clientId = stored.oauth_client_id ?? "";
  const secretHash = stored.oauth_client_secret_hash ?? "";
  if (!clientId || !secretHash) return null;
  let redirectUris: string[] = [];
  try {
    const parsed = JSON.parse(stored.oauth_redirect_uris || "[]");
    if (Array.isArray(parsed)) redirectUris = parsed.filter((value): value is string => typeof value === "string");
  } catch {
    redirectUris = [];
  }
  return { clientId, secretHash, redirectUris };
}

/**
 * Exact string match, deliberately. Prefix or host matching is where redirect
 * URI validation usually goes wrong, and Alexa's URIs are fixed and known.
 */
export function redirectAllowed(client: OAuthClient, redirectUri: string): boolean {
  return client.redirectUris.some((allowed) => safeEquals(allowed, redirectUri));
}

export async function issueCode(
  env: Env,
  accountId: string,
  client: OAuthClient,
  redirectUri: string,
  codeChallenge: string,
): Promise<string> {
  const code = randomToken();
  await env.DB.prepare(
    [
      "INSERT INTO oauth_codes (id, account_id, client_id, redirect_uri, code_challenge, expires_at)",
      "VALUES (?, ?, ?, ?, ?, ?)",
    ].join(" "),
  )
    .bind(
      await sha256Hex(code),
      accountId,
      client.clientId,
      redirectUri,
      codeChallenge,
      new Date(Date.now() + CODE_TTL_SECONDS * 1000).toISOString(),
    )
    .run();
  return code;
}

type CodeRow = { account_id: string; client_id: string; redirect_uri: string; code_challenge: string };

/** Base64url of the SHA-256 of the verifier, per RFC 7636's S256 method. */
export async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export async function redeemCode(
  env: Env,
  code: string,
  client: OAuthClient,
  redirectUri: string,
  verifier: string,
): Promise<string | null> {
  const id = await sha256Hex(code);
  const row = await env.DB.prepare(
    [
      "SELECT account_id, client_id, redirect_uri, code_challenge FROM oauth_codes",
      "WHERE id = ? AND used_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP",
    ].join(" "),
  )
    .bind(id)
    .first<CodeRow>();
  if (!row) return null;

  // Spend it before checking anything else, so a wrong verifier cannot be
  // retried against the same code.
  const spent = await env.DB.prepare(
    "UPDATE oauth_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL",
  )
    .bind(id)
    .run();
  if (!spent.meta.changes) return null;

  if (!safeEquals(row.client_id, client.clientId)) return null;
  if (!safeEquals(row.redirect_uri, redirectUri)) return null;
  if (!row.code_challenge || !verifier) return null;
  if (!safeEquals(await s256(verifier), row.code_challenge)) return null;
  return row.account_id;
}

export type IssuedTokens = { accessToken: string; refreshToken: string; expiresIn: number };

export async function issueTokens(env: Env, accountId: string, clientId: string): Promise<IssuedTokens> {
  const accessToken = randomToken();
  const refreshToken = randomToken();
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO oauth_tokens (id, account_id, client_id, kind, expires_at) VALUES (?, ?, ?, 'access', ?)",
    ).bind(await sha256Hex(accessToken), accountId, clientId, new Date(now + ACCESS_TTL_SECONDS * 1000).toISOString()),
    env.DB.prepare(
      "INSERT INTO oauth_tokens (id, account_id, client_id, kind, expires_at) VALUES (?, ?, ?, 'refresh', ?)",
    ).bind(await sha256Hex(refreshToken), accountId, clientId, new Date(now + REFRESH_TTL_SECONDS * 1000).toISOString()),
  ]);
  return { accessToken, refreshToken, expiresIn: ACCESS_TTL_SECONDS };
}

/** Resolves the account behind a bearer access token, or null. */
export async function accountIdFromAccessToken(env: Env, token: string): Promise<string | null> {
  if (!token) return null;
  const row = await env.DB.prepare(
    [
      "SELECT account_id FROM oauth_tokens",
      "WHERE id = ? AND kind = 'access' AND revoked_at IS NULL",
      "AND datetime(expires_at) > CURRENT_TIMESTAMP",
    ].join(" "),
  )
    .bind(await sha256Hex(token))
    .first<{ account_id: string }>();
  return row?.account_id ?? null;
}

export async function rotateRefreshToken(
  env: Env,
  refreshToken: string,
  clientId: string,
): Promise<IssuedTokens | null> {
  const id = await sha256Hex(refreshToken);
  const row = await env.DB.prepare(
    [
      "SELECT account_id, client_id, revoked_at FROM oauth_tokens",
      "WHERE id = ? AND kind = 'refresh' AND datetime(expires_at) > CURRENT_TIMESTAMP",
    ].join(" "),
  )
    .bind(id)
    .first<{ account_id: string; client_id: string; revoked_at: string | null }>();
  if (!row || !safeEquals(row.client_id, clientId)) return null;

  if (row.revoked_at) {
    // A retired refresh token being presented again means the chain leaked.
    // Drop every token for this account rather than quietly issuing more.
    await env.DB.prepare(
      "UPDATE oauth_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE account_id = ? AND revoked_at IS NULL",
    )
      .bind(row.account_id)
      .run();
    console.error("Reused OAuth refresh token; revoked every token for that account");
    return null;
  }

  const retired = await env.DB.prepare(
    "UPDATE oauth_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL",
  )
    .bind(id)
    .run();
  if (!retired.meta.changes) return null;

  const issued = await issueTokens(env, row.account_id, clientId);
  await env.DB.prepare("UPDATE oauth_tokens SET replaced_by = ? WHERE id = ?")
    .bind(await sha256Hex(issued.refreshToken), id)
    .run();
  return issued;
}

/** Ends every Alexa token for an account — the "unlink" side of linking. */
export async function revokeAccountTokens(env: Env, accountId: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE oauth_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE account_id = ? AND revoked_at IS NULL",
  )
    .bind(accountId)
    .run();
}

/** Reads client credentials from the request, header form or body form. */
export function clientCredentials(
  request: Request,
  form: URLSearchParams,
): { clientId: string; clientSecret: string } {
  const header = request.headers.get("authorization") ?? "";
  if (header.startsWith("Basic ")) {
    try {
      const [id, ...rest] = atob(header.slice(6)).split(":");
      return { clientId: decodeURIComponent(id ?? ""), clientSecret: decodeURIComponent(rest.join(":")) };
    } catch {
      // Fall through to the form fields below.
    }
  }
  return {
    clientId: form.get("client_id") ?? "",
    clientSecret: form.get("client_secret") ?? "",
  };
}
