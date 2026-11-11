export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Endpoint to view all digital products from your D1 database
      if (url.pathname === '/api/products' && request.method === 'GET') {
        const { results } = await env.DB.prepare("SELECT * FROM products ORDER BY created_at DESC").all();
        return jsonResponse({ success: true, products: results }, 200, corsHeaders);
      }

      // Endpoint to add a product or log a purchase
      if (url.pathname === '/api/products' && request.method === 'POST') {
        const body = await request.json();
        
        if (!body.id || !body.name || !body.price) {
          return jsonResponse({ success: false, error: 'Missing required fields: id, name, price' }, 400, corsHeaders);
        }

        await env.DB.prepare(
          "INSERT INTO products (id, name, price) VALUES (?, ?, ?)"
        ).bind(body.id, body.name, body.price).run();

        return jsonResponse({ success: true, message: 'Product recorded successfully' }, 201, corsHeaders);
      }

      return jsonResponse({ error: 'Endpoint not found' }, 404, corsHeaders);

    } catch (err) {
      return jsonResponse({ success: false, error: err.message }, 500, corsHeaders);
    }
  }
};

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}
