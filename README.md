# lunaneleholdings.com

Website and admin backend for Lunanele Holdings Pty Ltd, served by one Cloudflare Worker.

## What's in here

- `public/` — the public website (index.html, app.js, logo, security headers, sitemap)
- `worker.js` — public API and routing
  - `POST /api/enquiry` — saves an enquiry and emails it to relations@lunaneleholdings.com
- `admin.js` — the admin backend at **/admin**
  - Sign in with email + password (PBKDF2-hashed, stored in D1); 12-hour sessions
  - Lock-out after 5 failed sign-ins in 15 minutes
  - Same-site checks on every change; every change is written to the audit log
  - Website: enquiries · Sales: leads, customers, invoices, products, plans
  - Governance: companies & trusts, people, appointments, shareholdings, delegations,
    compliance diary, documents register, policies · Group finance: intercompany records
  - Search, CSV download, add / edit / delete (where allowed)
- `wrangler.toml` — Cloudflare settings (two D1 databases, email worker link)
- `migrations/` — database tables

## Deploy

Cloudflare builds and publishes automatically when you push to `main`.

## Admin accounts

Change your password at /admin/password after first sign-in.

Add another admin (run on a computer with Python and wrangler):

```
python3 -c "import hashlib,os,getpass;p=getpass.getpass();s=os.urandom(16).hex();print(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),100000).hex(),s)"
npx wrangler d1 execute lunanele-products-db --remote --command "INSERT INTO admin_users (email,pw_hash,pw_salt) VALUES ('name@lunaneleholdings.com','<hash>','<salt>')"
```

Disable an admin: `UPDATE admin_users SET active = 0 WHERE email = '...'`
