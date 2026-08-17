/**
 * ResellerClub Cloudflare-bypass proxy — Deno Deploy edition.
 *
 * httpapi.com (ResellerClub's API host) sits behind Cloudflare bot protection
 * that blocks default server User-Agents (including Deno's). This proxy sets a
 * browser User-Agent on the upstream request so Cloudflare lets it through.
 *
 * Deploy on Deno Deploy:
 *   1. Create a Deno Deploy project linked to your GitHub repo with this file
 *      as the entry point (e.g. main.ts).
 *   2. Set env var:  PROXY_TOKEN = <a long random string>
 *   3. (Optional) PROXY_TARGET = https://httpapi.com  (default)
 *   4. In Base44 → Settings → Secrets, set:
 *        RESELLERCLUB_PROXY_URL   = https://<your-deno-project>.deno.dev
 *        RESELLERCLUB_PROXY_TOKEN = <same PROXY_TOKEN>
 *
 * In ResellerClub control panel → Settings → API, set "Allow from all IPs"
 * (Deno Deploy uses shared egress IPs).
 */

const TOKEN = Deno.env.get("PROXY_TOKEN") ?? "";
const TARGET = Deno.env.get("PROXY_TARGET") ?? "https://httpapi.com";
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const target = new URL(TARGET);

// Hop-by-hop / proxy-specific headers we must not forward upstream.
const drop = new Set([
  "host",
  "x-proxy-token",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
]);

Deno.serve(async (req: Request): Promise<Response> => {
  // Health check on root
  const url = new URL(req.url);
  if (url.pathname === "/" && !url.search) {
    return new Response("ok", { headers: { "content-type": "text/plain" } });
  }

  // Token guard
  if (TOKEN && req.headers.get("x-proxy-token") !== TOKEN) {
    return new Response(JSON.stringify({ error: "forbidden" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }

  try {
    const upstream = new URL(target.origin + url.pathname + url.search);

    // Rebuild headers: drop hop-by-hop/proxy headers, force a browser UA.
    const headers = new Headers();
    for (const [k, v] of req.headers.entries()) {
      if (drop.has(k.toLowerCase())) continue;
      headers.set(k, v);
    }
    headers.set("host", target.host);
    headers.set("user-agent", UA);
    if (!headers.has("accept")) {
      headers.set("accept", "application/json, text/plain, */*");
    }

    // Forward the body verbatim for non-GET methods.
    const init: RequestInit = {
      method: req.method,
      headers,
    };
    if (req.method !== "GET" && req.method !== "HEAD") {
      init.body = await req.arrayBuffer();
    }

    const upstreamRes = await fetch(upstream.toString(), init);

    // Pass status + body + content-type through unchanged.
    const buf = await upstreamRes.arrayBuffer();
    const respHeaders = new Headers();
    for (const [k, v] of upstreamRes.headers.entries()) {
      if (drop.has(k.toLowerCase())) continue;
      respHeaders.set(k, v);
    }
    return new Response(buf, {
      status: upstreamRes.status,
      headers: respHeaders,
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: "upstream error", details: String(e?.message ?? e) }),
      { status: 502, headers: { "content-type": "application/json" } },
    );
  }
});
