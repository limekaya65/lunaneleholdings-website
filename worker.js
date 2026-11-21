// Lunanele Holdings website worker.
// Static files in /public are served automatically by Cloudflare (see wrangler.toml).
// This worker only handles the API routes below.

const json = (data, status = 200) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store" } });

const isAdmin = (request, env) => {
  const auth = request.headers.get("Authorization") || "";
  return Boolean(env.ADMIN_TOKEN) && auth === `Bearer ${env.ADMIN_TOKEN}`;
};

const clean = (v, max) => String(v ?? "").trim().slice(0, max);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

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
        return json({ ok: true });
      } catch (err) {
        console.error("enquiry insert failed", err);
        return json({ error: "Could not save enquiry" }, 500);
      }
    }

    // GET /api/enquiries — admin only (Authorization: Bearer <ADMIN_TOKEN>)
    if (url.pathname === "/api/enquiries" && request.method === "GET") {
      if (!isAdmin(request, env)) return json({ error: "Unauthorised" }, 401);
      const { results } = await env.DB.prepare(
        "SELECT * FROM enquiries ORDER BY created_at DESC LIMIT 200"
      ).all();
      return json(results);
    }

    // GET /products — admin only
    if (url.pathname === "/products" && request.method === "GET") {
      if (!isAdmin(request, env)) return json({ error: "Unauthorised" }, 401);
      const { results } = await env.DB.prepare(
        "SELECT * FROM products ORDER BY updated_at DESC"
      ).all();
      return json(results);
    }

    // POST /products — admin only
    if (url.pathname === "/products" && request.method === "POST") {
      if (!isAdmin(request, env)) return json({ error: "Unauthorised" }, 401);
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
