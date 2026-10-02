import { test } from "node:test";
import assert from "node:assert/strict";

import {
  absentAccountHash,
  cookieValue,
  hashPassword,
  needsRehash,
  sessionCookie,
  verifyPassword,
} from "../src/sign-in.ts";

// The functions under test read three fields off Env and nothing else.
const envWith = (settingsKey?: string) => ({ SETTINGS_KEY: settingsKey }) as unknown as Env;
const pepperEnv = (pepper?: string, previous?: string, settingsKey?: string) =>
  ({ PASSWORD_PEPPER: pepper, PASSWORD_PEPPER_PREVIOUS: previous, SETTINGS_KEY: settingsKey }) as unknown as Env;

const SECRET_A = "key-a-0000000000000000000000000000";
const SECRET_B = "key-b-1111111111111111111111111111";
const KEY_A = envWith(SECRET_A);
const KEY_B = envWith(SECRET_B);

/** The same hash as it would have been written before pepper fingerprinting. */
const asLegacy = (stored: string): string => {
  const [, hash, iterations, , salt, digest] = stored.split("$");
  return `pbkdf2p$${hash}$${iterations}$${salt}$${digest}`;
};

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
  assert.equal(scheme, "pbkdf2p2");
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
  assert.ok(stored.startsWith("pbkdf2p2$"));
  const downgraded = asLegacy(stored).replace("pbkdf2p$", "pbkdf2$");
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

test("a hash written before the pepper was fingerprinted still verifies", async () => {
  // There is nothing to migrate: every row already in the database was written
  // by the scheme this one replaces, and must keep working untouched.
  const legacy = asLegacy(await hashPassword(KEY_A, "correct horse battery"));
  assert.equal(await verifyPassword(KEY_A, "correct horse battery", legacy), true);
  assert.equal(await verifyPassword(KEY_A, "wrong password", legacy), false);
  assert.equal(await verifyPassword(KEY_B, "correct horse battery", legacy), false);
});

test("a hash is due a re-write when its pepper is not the current one", async () => {
  assert.equal(await needsRehash(KEY_A, asLegacy(await hashPassword(KEY_A, "x"))), true);
  assert.equal(await needsRehash(KEY_A, await hashPassword(KEY_A, "x")), false);
});

test("a dedicated pepper is preferred to the settings key", async () => {
  const stored = await hashPassword(pepperEnv(SECRET_A, undefined, SECRET_B), "correct horse battery");
  assert.equal(await verifyPassword(envWith(SECRET_A), "correct horse battery", stored), true);
  // Written under PASSWORD_PEPPER, so the settings key alone must not open it.
  assert.equal(await verifyPassword(envWith(SECRET_B), "correct horse battery", stored), false);
});

test("rotating the pepper is a rotation rather than a lockout", async () => {
  // The failure this scheme exists to prevent: a secret changes for an
  // unrelated reason and every password in the database stops working, with
  // nothing said about why.
  const before = await hashPassword(pepperEnv(SECRET_A), "correct horse battery");
  const during = pepperEnv(SECRET_B, SECRET_A);
  assert.equal(await verifyPassword(during, "correct horse battery", before), true);
  // Due a re-write, which is what lets the old secret eventually be dropped.
  assert.equal(await needsRehash(during, before), true);
  // And once it is dropped, the old hash is genuinely closed.
  assert.equal(await verifyPassword(pepperEnv(SECRET_B), "correct horse battery", before), false);
});

test("an address with no account is checked at the same cost as a real one", async () => {
  const absent = await absentAccountHash(KEY_A);
  const real = await hashPassword(KEY_A, "x");
  // Same scheme, cost and pepper, so the work spent is identical and the delay
  // does not say whether the address exists.
  assert.deepEqual(absent.split("$").slice(0, 4), real.split("$").slice(0, 4));
  assert.equal(await verifyPassword(KEY_A, "x", absent), false);
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
