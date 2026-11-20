# lunaneleholdings.com

One-page website for Lunanele Holdings Pty Ltd, served by a Cloudflare Worker.

- `public/` — the website (static files)
- `worker.js` — API: `POST /api/enquiry` (contact form → D1 `enquiries` table), `GET /api/enquiries` (admin), `GET/POST /products` (admin)
- `migrations/` — D1 schema

Deploy: `npx wrangler deploy`
Read enquiries: `npx wrangler d1 execute lunanele-products-db --remote --command "SELECT * FROM enquiries ORDER BY created_at DESC"`
Admin token for protected routes: `npx wrangler secret put ADMIN_TOKEN`
