import { test } from "node:test";
import assert from "node:assert/strict";

import { hashPassword, verifyPassword, cookieValue, sessionCookie } from "../src/sign-in.ts";

// The functions under test read one field off Env and nothing else.
const envWith = (settingsKey?: string) => ({ SETTINGS_KEY: settingsKey }) as unknown as Env;

const KEY_A = envWith("key-a-0000000000000000000000000000");
const KEY_B = envWith("key-b-1111111111111111111111111111");

test("a password verifies against its own hash", async () => {
  const stored = await hashPassword(KEY_A, "correct horse battery");
  assert.equal(await verifyPassword(KEY_A, "correct horse battery", stored), true);
});

test("a wrong password does not", async () => {
  const stored = await hashPassword(KEY_A, "correct horse battery");
  assert.equal(await verifyPassword(KEY_A, "correct horse batteru", stored), false);
});

test("the same password hashes differently every time", async () => {
  // Salted, so two accounts sharing a password are not visibly the same.
  const first = await hashPassword(KEY_A, "same password");
  const second = await hashPassword(KEY_A, "same password");
  assert.notEqual(first, second);
});

test("the hash records the cost and stays inside the Workers ceiling", async () => {
  const [scheme, digest, iterations] = (await hashPassword(KEY_A, "x")).split("$");
  assert.equal(scheme, "pbkdf2p");
  assert.equal(digest, "sha256");
  // Workers refuses PBKDF2 above 100,000 iterations at runtime. A hash written
  // above that would verify nowhere.
  assert.ok(Number(iterations) <= 100_000);
});

test("a hash is worthless without the pepper key", async () => {
  const stored = await hashPassword(KEY_A, "correct horse battery");
  // This is the property that compensates for the low iteration ceiling: a
  // stolen database cannot be attacked without a secret Cloudflare will not
  // hand back.
  assert.equal(await verifyPassword(KEY_B, "correct horse battery", stored), false);
  assert.equal(await verifyPassword(envWith(), "correct horse battery", stored), false);
});

test("a peppered hash is never checked as an unpeppered one", async () => {
  const stored = await hashPassword(KEY_A, "correct horse battery");
  assert.ok(stored.startsWith("pbkdf2p$"));
  const downgraded = stored.replace("pbkdf2p$", "pbkdf2$");
  // Rewriting the scheme must not turn into a way to skip the pepper.
  assert.equal(await verifyPassword(KEY_A, "correct horse battery", downgraded), false);
});

test("malformed stored hashes are rejected rather than throwing", async () => {
  for (const stored of ["", "nonsense", "pbkdf2p$sha256$", "pbkdf2p$sha1$100000$aa$bb", "pbkdf2p$sha256$0$aa$bb"]) {
    assert.equal(await verifyPassword(KEY_A, "anything", stored), false, stored);
  }
});

test("an absurd iteration count cannot be forced through a stored hash", async () => {
  // A tampered row must not be able to make the runtime refuse the request.
  const stored = "pbkdf2p$sha256$999999999$aabb$ccdd";
  assert.equal(await verifyPassword(KEY_A, "anything", stored), false);
});

test("the session cookie cannot be read by script and is not sent cross-site", () => {
  const header = sessionCookie("value", 100);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Secure/);
  assert.match(header, /SameSite=Lax/);
});

test("cookie parsing picks the right name and tolerates absence", () => {
  assert.equal(cookieValue("a=1; df_session=abc; b=2", "df_session"), "abc");
  assert.equal(cookieValue("df_session_other=abc", "df_session"), "");
  assert.equal(cookieValue(null, "df_session"), "");
});
