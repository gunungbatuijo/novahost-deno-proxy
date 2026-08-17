const UPSTREAM = "https://httpapi.com";
const PROXY_TOKEN = Deno.env.get("PROXY_TOKEN");

Deno.serve(async (req) => {
  const url = new URL(req.url);

  // health check
  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
    return new Response("ok", { status: 200 });
  }

  // optional token guard
  if (PROXY_TOKEN) {
    const auth = req.headers.get("x-proxy-token");
    if (auth !== PROXY_TOKEN) {
      return new Response("unauthorized", { status: 401 });
    }
  }

  // build upstream URL: append everything after the first slash
  const upstream = new URL(url.pathname.slice(1) + url.search, UPSTREAM);

  // forward headers, drop hop-by-hop + auth header
  const headers = new Headers();
  for (const [k, v] of req.headers.entries()) {
    const lk = k.toLowerCase();
    if (["host", "connection", "x-proxy-token"].includes(lk)) continue;
    headers.set(k, v);
  }
  headers.set("host", upstream.host);

  const upstreamRes = await fetch(upstream, {
    method: req.method,
    headers,
    body: req.body,
  });

  return new Response(upstreamRes.body, {
    status: upstreamRes.status,
    headers: upstreamRes.headers,
  });
});
