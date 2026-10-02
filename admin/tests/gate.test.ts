// The admin host carries owner credentials to the build on every proxied
// request, so the only property that really matters is that it refuses when it
// is not certain who is asking. These cover the refusals, not the happy path,
// which needs a real Access token to exercise.

import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/index.ts";

const CONFIGURED = {
  ACCESS_TEAM_DOMAIN: "https://birniger.cloudflareaccess.com",
  POLICY_AUD: "a".repeat(64),
  OWNER_EMAIL: "owner@example.com",
  PANEL_TOKEN: "panel-token",
  BUILD: { fetch: async () => new Response("upstream reached", { status: 200 }) },
};

const get = (path: string, headers: Record<string, string> = {}) =>
  new Request(`https://device-finder-admin.example.dev${path}`, { headers });

test("an unconfigured admin host refuses rather than proxying", async () => {
  for (const missing of ["ACCESS_TEAM_DOMAIN", "POLICY_AUD", "OWNER_EMAIL", "PANEL_TOKEN"]) {
    const env = { ...CONFIGURED, [missing]: "" };
    const response = await worker.fetch(get("/admin"), env as never);
    assert.equal(response.status, 503, `${missing} missing should fail closed`);
  }
});

test("a request with no Access assertion is refused", async () => {
  const response = await worker.fetch(get("/admin"), CONFIGURED as never);
  assert.equal(response.status, 403);
});

test("a forged Access assertion is refused", async () => {
  const response = await worker.fetch(
    get("/admin", { "cf-access-jwt-assertion": "not.a.jwt" }),
    CONFIGURED as never,
  );
  assert.equal(response.status, 403);
});

test("the local bypass only applies to localhost", async () => {
  const env = { ...CONFIGURED, LOCAL_DEV_BYPASS: "true" };
  const remote = await worker.fetch(get("/admin"), env as never);
  assert.equal(remote.status, 403, "the bypass must not apply to the deployed host");

  const local = await worker.fetch(
    new Request("http://localhost:8787/admin"),
    env as never,
  );
  assert.equal(local.status, 200);
});

test("paths outside the allowlist are not proxied even for the owner", async () => {
  const env = { ...CONFIGURED, LOCAL_DEV_BYPASS: "true" };
  // /oauth/authorize would otherwise be reachable while holding owner
  // credentials, and the runner endpoints are not the owner's to call.
  for (const path of ["/oauth/authorize", "/api/runner/jobs", "/api/auth/sign-in", "/api/status"]) {
    const response = await worker.fetch(new Request(`http://localhost:8787${path}`), env as never);
    assert.equal(response.status, 404, `${path} should not be proxied`);
  }
});

test("the root redirects to /admin so the SPA renders the owner view", async () => {
  const env = { ...CONFIGURED, LOCAL_DEV_BYPASS: "true" };
  const response = await worker.fetch(new Request("http://localhost:8787/"), env as never);
  assert.equal(response.status, 302);
  assert.equal(new URL(response.headers.get("location") ?? "").pathname, "/admin");
});

test("the Access assertion and inbound cookies do not travel to the build", async () => {
  let forwarded: Headers | null = null;
  const env = {
    ...CONFIGURED,
    LOCAL_DEV_BYPASS: "true",
    BUILD: {
      fetch: async (request: Request) => {
        forwarded = request.headers;
        return new Response("ok", { status: 200, headers: { "set-cookie": "build_session=abc" } });
      },
    },
  };
  const response = await worker.fetch(
    new Request("http://localhost:8787/api/admin/summary", {
      headers: {
        "cf-access-jwt-assertion": "leak-me",
        cookie: "df_session=someone-elses",
        authorization: "Bearer an-attackers-token",
      },
    }),
    env as never,
  );

  assert.equal(response.status, 200);
  assert.equal(forwarded!.get("cf-access-jwt-assertion"), null);
  assert.equal(forwarded!.get("cookie"), null);
  assert.equal(forwarded!.get("authorization"), "Bearer panel-token");
  // A cookie scoped to the build's host would be set on the admin host here.
  assert.equal(response.headers.get("set-cookie"), null);
});
