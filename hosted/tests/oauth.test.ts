import { test } from "node:test";
import assert from "node:assert/strict";

import { parseClient, redirectAllowed, s256, safeEquals, randomToken } from "../src/oauth.ts";

const client = (uris: string[]) => ({ clientId: "c", secretHash: "h", redirectUris: uris });

test("PKCE S256 matches the RFC 7636 vector", async () => {
  // Appendix B of RFC 7636. If this drifts, every code exchange breaks.
  assert.equal(
    await s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
});

test("the challenge is base64url, with no padding or unsafe characters", async () => {
  const challenge = await s256(randomToken());
  assert.doesNotMatch(challenge, /[+/=]/);
});

test("redirect addresses match exactly, never by prefix", () => {
  const allowed = "https://layla.amazon.com/api/skill/link/VENDOR";
  const registered = client([allowed]);
  assert.equal(redirectAllowed(registered, allowed), true);
  // Each of these is a way redirect validation is usually got wrong.
  for (const attacker of [
    "https://layla.amazon.com/api/skill/link/VENDOR/../../evil",
    "https://layla.amazon.com/api/skill/link/VENDORX",
    "https://layla.amazon.com/api/skill/link/VENDOR?x=1",
    "https://layla.amazon.com.evil.example/api/skill/link/VENDOR",
    "https://evil.example/api/skill/link/VENDOR",
    "http://layla.amazon.com/api/skill/link/VENDOR",
    "",
  ]) {
    assert.equal(redirectAllowed(registered, attacker), false, attacker);
  }
});

test("no registered address means nothing is allowed", () => {
  assert.equal(redirectAllowed(client([]), "https://layla.amazon.com/x"), false);
});

test("comparison is length-aware and value-correct", () => {
  assert.equal(safeEquals("abc", "abc"), true);
  assert.equal(safeEquals("abc", "abd"), false);
  assert.equal(safeEquals("abc", "abcd"), false);
  assert.equal(safeEquals("", ""), true);
});

test("a client is only usable once it has both an id and a secret", () => {
  assert.equal(parseClient({}), null);
  assert.equal(parseClient({ oauth_client_id: "c" }), null);
  assert.equal(parseClient({ oauth_client_secret_hash: "h" }), null);
  assert.deepEqual(parseClient({ oauth_client_id: "c", oauth_client_secret_hash: "h" }), {
    clientId: "c",
    secretHash: "h",
    redirectUris: [],
  });
});

test("a corrupt redirect list leaves nothing allowed rather than throwing", () => {
  const parsed = parseClient({
    oauth_client_id: "c",
    oauth_client_secret_hash: "h",
    oauth_redirect_uris: "{ not json",
  });
  assert.deepEqual(parsed?.redirectUris, []);
});

test("non-string entries are dropped from the redirect list", () => {
  const parsed = parseClient({
    oauth_client_id: "c",
    oauth_client_secret_hash: "h",
    oauth_redirect_uris: JSON.stringify(["https://ok.example/cb", 5, null, { a: 1 }]),
  });
  assert.deepEqual(parsed?.redirectUris, ["https://ok.example/cb"]);
});

test("tokens are long and do not repeat", () => {
  const seen = new Set(Array.from({ length: 200 }, () => randomToken()));
  assert.equal(seen.size, 200);
  assert.equal(randomToken().length, 64);
});
