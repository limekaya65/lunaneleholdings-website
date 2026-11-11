export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle CORS preflight requests if needed
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // GET /products - Fetch all products
    if (url.pathname === "/products" && request.method === "GET") {
      try {
        const { results } = await env.DB.prepare(
          "SELECT * FROM products ORDER BY created_at DESC"
        ).all();

        return Response.json(results, {
          headers: { "Access-Control-Allow-Origin": "*" },
        });
      } catch (err) {
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    // POST /products - Add a new product
    if (url.pathname === "/products" && request.method === "POST") {
      try {
        const body = await request.json();

        // Fixed validation: checks if price is explicitly undefined/null rather than treating 0 as falsy
        if (!body.id || !body.name || body.price === undefined || body.price === null) {
          return Response.json({ error: "Missing required fields (id, name, price)" }, { status: 400 });
        }

        await env.DB.prepare(
          "INSERT INTO products (id, name, price) VALUES (?, ?, ?)"
        )
          .bind(body.id, body.name, body.price)
          .run();

        return Response.json({ success: true }, {
          headers: { "Access-Control-Allow-Origin": "*" },
        });
      } catch (err) {
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};
