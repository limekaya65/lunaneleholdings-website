import { handleAdmin, currentUser } from "./admin.js";

// Lunanele Holdings website worker.
// Static files in /public are served automatically by Cloudflare (see wrangler.toml).
// This worker only handles the API routes below.

const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" },
  });

// Admin = signed-in admin session, or (for scripts) a Bearer ADMIN_TOKEN secret.
const isAdmin = async (request, env) => {
  const auth = request.headers.get("Authorization") || "";
  if (env.ADMIN_TOKEN && env.ADMIN_TOKEN.length >= 24 && auth === `Bearer ${env.ADMIN_TOKEN}`) return true;
  return Boolean(await currentUser(request, env));
};

const clean = (v, max) => String(v ?? "").trim().slice(0, max);

// Strip anything that could be read as HTML before it goes into an email.
const plain = (v) => String(v).replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" })[c]);

// Emails relations@ via the lunanele-email worker (service binding, never public internet).
async function notify(env, e) {
  if (!env.EMAILER) return;
  try {
    await env.EMAILER.fetch("https://lunanele-email/api/contact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: plain(`${e.name}${e.organisation ? " (" + e.organisation + ")" : ""}`),
        email: plain(e.email),
        message: plain(`[Website enquiry: ${e.topic || "General"}]\n\n${e.message}`),
      }),
    });
  } catch (err) {
    console.error("enquiry email failed", err);
  }
}

// Luna Cybersecurity's free check and its linked pages live on the lunanele-gateway
// Worker. Serving them here keeps visitors on lunaneleholdings.com, which is the
// address on the flyer and QR code. The gateway sees the original URL, so links it
// builds (such as emailed report links) also use lunaneleholdings.com.
const GATEWAY_ORIGIN = "https://lunanele-gateway.limekayawelile.workers.dev";
const GATEWAY_PATHS = new Set(["/security", "/quote", "/pricing", "/privacy", "/terms"]);

function isGatewayPath(pathname) {
  const p = pathname.replace(/\/+$/, "") || "/";
  return GATEWAY_PATHS.has(p) || p.startsWith("/security/");
}

async function toGateway(request, env, url) {
  if (env.GATEWAY) return env.GATEWAY.fetch(request);
  // Without the service binding, send the visitor to the gateway directly.
  return Response.redirect(GATEWAY_ORIGIN + url.pathname + url.search, 302);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (isGatewayPath(url.pathname)) {
      try {
        return await toGateway(request, env, url);
      } catch (err) {
        console.error("gateway proxy error", err);
        return Response.redirect(GATEWAY_ORIGIN + url.pathname + url.search, 302);
      }
    }

    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) {
      try {
        return await handleAdmin(request, env);
      } catch (err) {
        console.error("admin error", err);
        return new Response("Something went wrong. Please try again.", { status: 500, headers: { "Cache-Control": "no-store" } });
      }
    }

    // POST /api/enquiry — public contact form
    if (url.pathname === "/api/enquiry" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid request" }, 400);
      }
      if (body.website) return json({ ok: true }); // honeypot: silently drop bots

      const name = clean(body.name, 120);
      const email = clean(body.email, 200);
      const organisation = clean(body.organisation, 160);
      const topic = clean(body.topic, 80);
      const message = clean(body.message, 4000);

      if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || message.length < 10) {
        return json({ error: "Please provide your name, a valid email and a message." }, 400);
      }

      // Spam limits: 3 per sender per hour, 60 site-wide per hour.
      const { results: [lim] } = await env.DB.prepare(
        "SELECT SUM(email = ?) AS mine, COUNT(*) AS total FROM enquiries WHERE created_at > datetime('now', '-1 hour')"
      ).bind(email).all();
      if ((lim?.mine ?? 0) >= 3 || (lim?.total ?? 0) >= 60) {
        return json({ error: "Too many enquiries. Please try again later or WhatsApp us." }, 429);
      }

      try {
        await env.DB.prepare(
          "INSERT INTO enquiries (name, email, organisation, topic, message, country, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
          .bind(
            name, email, organisation, topic, message,
            request.cf?.country || null,
            clean(request.headers.get("User-Agent"), 300)
          )
          .run();
        ctx.waitUntil(notify(env, { name, email, organisation, topic, message }));
        return json({ ok: true });
      } catch (err) {
        console.error("enquiry insert failed", err);
        return json({ error: "Could not save enquiry" }, 500);
      }
    }

    // GET /api/enquiries — admin only (Authorization: Bearer <ADMIN_TOKEN>)
    if (url.pathname === "/api/enquiries" && request.method === "GET") {
      if (!(await isAdmin(request, env))) return json({ error: "Unauthorised" }, 401);
      const { results } = await env.DB.prepare(
        "SELECT * FROM enquiries ORDER BY created_at DESC LIMIT 200"
      ).all();
      return json(results);
    }

    // GET /products — admin only
    if (url.pathname === "/products" && request.method === "GET") {
      if (!(await isAdmin(request, env))) return json({ error: "Unauthorised" }, 401);
      const { results } = await env.DB.prepare(
        "SELECT * FROM products ORDER BY updated_at DESC"
      ).all();
      return json(results);
    }

    // POST /products — admin only
    if (url.pathname === "/products" && request.method === "POST") {
      if (!(await isAdmin(request, env))) return json({ error: "Unauthorised" }, 401);
      const b = await request.json().catch(() => ({}));
      if (!b.id || !b.name) return json({ error: "Missing required fields (id, name)" }, 400);
      await env.DB.prepare(
        "INSERT INTO products (id, name, owner_entity, description, status, url) VALUES (?, ?, ?, ?, ?, ?)"
      )
        .bind(b.id, b.name, b.owner_entity ?? null, b.description ?? null, b.status ?? "building", b.url ?? null)
        .run();
      return json({ ok: true });
    }

    // Anything else that isn't a static file: send people to the homepage.
    if (env.ASSETS) return env.ASSETS.fetch(new Request(new URL("/", url), request));
    return new Response("Not Found", { status: 404 });
  },
};
