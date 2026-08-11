// The owner's way into Device Finder, on a hostname of its own.
//
// On workers.dev a Worker gets exactly one hostname, so a separate admin URL
// means a separate Worker. This one holds no UI and no database: Cloudflare
// Access identifies the owner at the edge, and everything after that is
// forwarded to the Device Finder Worker over a service binding, carrying the
// panel token it already accepts.
//
// It fails closed. With no Access configuration it answers 503, and with no
// valid Access token it answers 403 — so deploying this before the Access
// application exists exposes nothing.

import { createRemoteJWKSet, jwtVerify } from "jose";

type Env = {
  ACCESS_TEAM_DOMAIN: string;
  POLICY_AUD: string;
  OWNER_EMAIL: string;
  /** Matches MY_BUILDS_STATUS_TOKEN on the Device Finder Worker. */
  PANEL_TOKEN: string;
  BUILD: { fetch: (request: Request) => Promise<Response> };
  LOCAL_DEV_BYPASS?: string;
};

let keys: ReturnType<typeof createRemoteJWKSet> | null = null;

function accessKeys(teamDomain: string) {
  keys ??= createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
  return keys;
}

function denied(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" },
  });
}

async function ownerIsPresent(request: Request, env: Env): Promise<boolean> {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return false;
  const teamDomain = env.ACCESS_TEAM_DOMAIN.replace(/\/$/, "");
  try {
    const { payload } = await jwtVerify(token, accessKeys(teamDomain), {
      issuer: teamDomain,
      audience: env.POLICY_AUD,
    });
    return typeof payload.email === "string" &&
      payload.email.toLowerCase() === env.OWNER_EMAIL.toLowerCase();
  } catch {
    return false;
  }
}

// An allowlist rather than a denylist. Every request leaving here carries owner
// credentials, so a path nobody thought about must not inherit them by default.
const PROXIED = [
  "/admin",
  "/api/admin/",
  "/api/owner/",
  "/api/me",
  "/api/config",
  "/api/auth/sign-out",
];
const ASSETS = ["/app.js", "/styles.css", "/favicon.svg", "/manifest.webmanifest"];

function isProxied(path: string): boolean {
  return PROXIED.some((prefix) => path === prefix || path.startsWith(prefix)) || ASSETS.includes(path);
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.ACCESS_TEAM_DOMAIN || !env.POLICY_AUD || !env.OWNER_EMAIL) {
      return denied(503, "Admin access is being configured.");
    }
    if (!env.PANEL_TOKEN) return denied(503, "Admin access is being configured.");

    const hostname = new URL(request.url).hostname;
    const localBypass = env.LOCAL_DEV_BYPASS === "true" &&
      (hostname === "localhost" || hostname === "127.0.0.1");
    if (!localBypass && !(await ownerIsPresent(request, env))) {
      return denied(403, "Access denied.");
    }

    const url = new URL(request.url);
    // The admin UI is one SPA that decides what to render from the path, so the
    // browser has to actually be at /admin — serving it from / would render the
    // tester dashboard instead.
    if (url.pathname === "/") {
      return Response.redirect(new URL("/admin", url).toString(), 302);
    }
    if (!isProxied(url.pathname)) return denied(404, "Not found.");

    const headers = new Headers(request.headers);
    // The build Worker trusts this token completely, which is exactly why the
    // Access assertion must not travel with it.
    headers.delete("cf-access-jwt-assertion");
    headers.delete("cookie");
    headers.set("authorization", `Bearer ${env.PANEL_TOKEN}`);

    const upstream = new URL(url.pathname + url.search, "https://device-finder.internal");
    const response = await env.BUILD.fetch(
      new Request(upstream.toString(), {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      }),
    );
    // Cookies the build sets are scoped to its own host and mean nothing here;
    // dropping them keeps the two sessions from being confused for each other.
    const out = new Headers(response.headers);
    out.delete("set-cookie");
    out.set("cache-control", "no-store");
    return new Response(response.body, { status: response.status, headers: out });
  },
} satisfies ExportedHandler<Env>;

export default worker;
