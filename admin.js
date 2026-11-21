// Lunanele admin backend — served at /admin by the website worker.
// Sign-in with email + password (PBKDF2 hash in D1), sessions stored in D1,
// same-origin checks on every change, login lock-out, and an audit trail.

const COOKIE = "__Host-lun_admin";
const SESSION_HOURS = 12;
const PBKDF2_ITERATIONS = 100000;
const MAX_FAILS = 5; // per IP per 15 minutes

// ---------- Resources (only tables/columns listed here are reachable) ----------
const ENQ_STATUS = ["new", "replied", "closed", "spam"];
const LEAD_STATUS = ["new", "contacted", "quoted", "won", "lost"];
const ENTITY_TYPES = ["trust", "holding", "subsidiary", "spv"];

const RESOURCES = {
  enquiries: {
    db: "DB", group: "Website", title: "Enquiries", pk: "id", order: "created_at DESC",
    list: ["id", "created_at", "name", "email", "organisation", "topic", "status"],
    fields: { status: { type: "select", options: ENQ_STATUS } },
    show: ["name", "email", "organisation", "topic", "message", "country", "created_at"],
    create: false,
  },
  leads: {
    db: "DB", group: "Sales", title: "Leads", pk: "id", order: "created_at DESC",
    list: ["id", "created_at", "name", "email", "company", "product_id", "plan_id", "status"],
    fields: { status: { type: "select", options: LEAD_STATUS } },
    show: ["name", "email", "phone", "company", "product_id", "plan_id", "quantity", "message", "source", "created_at"],
    touch: "updated_at", create: false,
  },
  customers: {
    db: "DB", group: "Sales", title: "Customers", pk: "id", order: "created_at DESC",
    list: ["id", "name", "email", "company", "country", "status", "created_at"],
    fields: {
      name: { type: "text", required: true }, email: { type: "email", required: true },
      company: { type: "text" }, country: { type: "text" }, vat_no: { type: "text" },
      status: { type: "select", options: ["active", "suspended", "closed"] },
    },
  },
  subscriptions: {
    db: "DB", group: "Sales", title: "Subscriptions", pk: "id", order: "started_at DESC",
    list: ["id", "customer_id", "plan_id", "seats", "status", "started_at"],
    fields: {
      customer_id: { type: "ref", ref: "customers", required: true },
      plan_id: { type: "ref", ref: "plans", required: true },
      seats: { type: "number" },
      status: { type: "select", options: ["active", "past_due", "cancelled"] },
    },
  },
  invoices: {
    db: "DB", group: "Sales", title: "Invoices", pk: "id", order: "created_at DESC",
    list: ["id", "reference", "customer_id", "billing_entity", "period", "total_zar", "status", "created_at"],
    fields: { status: { type: "select", options: ["open", "paid", "void"] } },
    create: false, del: false,
  },
  products: {
    db: "DB", group: "Sales", title: "Products", pk: "id", order: "name",
    list: ["id", "name", "owner_entity", "status"],
    fields: { name: { type: "text", required: true }, description: { type: "textarea" }, status: { type: "text" }, url: { type: "text" } },
    create: false, del: false,
  },
  plans: {
    db: "DB", group: "Sales", title: "Plans & prices", pk: "id", order: "product_id, sort_order",
    list: ["id", "product_id", "name", "billing_type", "price_zar", "status", "active"],
    fields: {
      name: { type: "text", required: true }, description: { type: "textarea" },
      price_zar: { type: "number" }, status: { type: "select", options: ["draft", "live", "private"] },
      active: { type: "select", options: ["1", "0"] },
    },
    create: false, del: false,
  },
  sec_assets: {
    db: "DB", group: "Luna Cybersecurity", title: "Monitored domains", pk: "id", order: "created_at DESC",
    list: ["id", "customer_id", "domain", "status", "last_grade", "last_score", "last_scan_at"],
    fields: {
      customer_id: { type: "ref", ref: "customers", required: true }, domain: { type: "text", required: true },
      status: { type: "select", options: ["active", "paused"] },
    },
  },
  sec_alerts: {
    db: "DB", group: "Luna Cybersecurity", title: "Security alerts", pk: "id", order: "id DESC",
    list: ["id", "created_at", "asset_id", "severity", "message"], fields: {}, create: false, del: false, readonly: true,
  },
  sec_portals: {
    db: "DB", group: "Luna Cybersecurity", title: "Customer dashboard links", pk: "customer_id", order: "created_at DESC",
    list: ["customer_id", "portal_url", "created_at"], fields: {}, create: false, del: false, readonly: true,
  },
  sec_events: {
    db: "DB", group: "Luna Cybersecurity", title: "Security events (attacks)", pk: "id", order: "id DESC",
    list: ["id", "created_at", "ip", "kind", "action", "country", "path"], fields: {}, create: false, del: false, readonly: true,
  },
  sec_ip_rules: {
    db: "DB", group: "Luna Cybersecurity", title: "IP block / allow list", pk: "ip", pkText: true, order: "created_at DESC",
    list: ["ip", "rule", "reason", "created_at"],
    fields: {
      ip: { type: "text", required: true }, rule: { type: "select", options: ["block", "allow"] }, reason: { type: "text" },
    },
  },
  entities: {
    db: "HDB", group: "Governance", title: "Companies & trusts", pk: "id", pkText: true, order: "entity_type, name",
    list: ["id", "name", "entity_type", "parent_id", "registration_no", "status"],
    fields: {
      name: { type: "text", required: true }, entity_type: { type: "select", options: ENTITY_TYPES, required: true },
      parent_id: { type: "ref", ref: "entities" }, registration_no: { type: "text" },
      status: { type: "select", options: ["active", "pending", "dormant", "deregistered"] },
      public_facing: { type: "select", options: ["1", "0"] }, notes: { type: "textarea" },
    },
    touch: "updated_at",
  },
  people: {
    db: "HDB", group: "Governance", title: "People", pk: "id", pkText: true, order: "full_name",
    list: ["id", "full_name", "email", "phone"],
    fields: { full_name: { type: "text", required: true }, email: { type: "email" }, phone: { type: "text" }, notes: { type: "textarea" } },
  },
  appointments: {
    db: "HDB", group: "Governance", title: "Appointments", pk: "id", order: "entity_id",
    list: ["id", "entity_id", "person_id", "role", "start_date", "end_date"],
    fields: {
      entity_id: { type: "ref", ref: "entities", required: true }, person_id: { type: "ref", ref: "people", required: true },
      role: { type: "text", required: true }, start_date: { type: "date" }, end_date: { type: "date" }, notes: { type: "textarea" },
    },
  },
  shareholdings: {
    db: "HDB", group: "Governance", title: "Shareholdings", pk: "id", order: "entity_id",
    list: ["id", "entity_id", "holder_entity_id", "holder_person_id", "percentage", "share_class", "status"],
    fields: {
      entity_id: { type: "ref", ref: "entities", required: true }, holder_entity_id: { type: "ref", ref: "entities" },
      holder_person_id: { type: "ref", ref: "people" }, percentage: { type: "number" }, share_class: { type: "text" },
      status: { type: "select", options: ["intended", "issued", "transferred"] }, notes: { type: "textarea" },
    },
  },
  delegations: {
    db: "HDB", group: "Governance", title: "Delegations of authority", pk: "id", order: "entity_id",
    list: ["id", "entity_id", "delegate_person_id", "authority", "limit_zar", "status"],
    fields: {
      entity_id: { type: "ref", ref: "entities", required: true }, delegate_person_id: { type: "ref", ref: "people", required: true },
      authority: { type: "textarea", required: true }, limit_zar: { type: "number" }, start_date: { type: "date" },
      end_date: { type: "date" }, approved_by: { type: "text" }, status: { type: "select", options: ["active", "suspended", "ended"] },
    },
  },
  compliance: {
    db: "HDB", group: "Governance", title: "Compliance diary", pk: "id", order: "due_date",
    list: ["id", "entity_id", "item", "due_date", "status"],
    fields: {
      entity_id: { type: "ref", ref: "entities" }, item: { type: "text", required: true }, due_date: { type: "date" },
      status: { type: "select", options: ["open", "done", "overdue"] }, notes: { type: "textarea" },
    },
  },
  documents: {
    db: "HDB", group: "Governance", title: "Documents register", pk: "id", order: "updated_at DESC",
    list: ["id", "entity_id", "title", "doc_type", "version", "status"],
    fields: {
      entity_id: { type: "ref", ref: "entities" }, title: { type: "text", required: true }, doc_type: { type: "text" },
      version: { type: "text" }, status: { type: "select", options: ["draft", "final", "signed", "superseded"] },
    },
    touch: "updated_at",
  },
  policies: {
    db: "HDB", group: "Governance", title: "Policies", pk: "id", pkText: true, order: "title",
    list: ["id", "title", "scope", "effective_date"],
    fields: { title: { type: "text", required: true }, scope: { type: "text" }, summary: { type: "textarea" }, source_document: { type: "text" }, effective_date: { type: "date" } },
  },
  intercompany_agreements: {
    db: "HDB", group: "Group finance", title: "Intercompany agreements", pk: "id", order: "subsidiary_id",
    list: ["id", "subsidiary_id", "service", "basis", "amount_zar", "percent", "status"],
    fields: { status: { type: "select", options: ["draft", "signed", "ended"] } },
    create: false, del: false,
  },
  intercompany_invoices: {
    db: "HDB", group: "Group finance", title: "Intercompany invoices", pk: "id", order: "period DESC",
    list: ["id", "subsidiary_id", "period", "description", "total_zar", "status"],
    fields: { status: { type: "select", options: ["draft", "issued", "paid", "void"] } },
    create: false, del: false,
  },
  audit_log: {
    db: "HDB", group: "System", title: "Audit log", pk: "id", order: "id DESC",
    list: ["id", "at", "actor", "action", "detail"], fields: {}, create: false, del: false, readonly: true,
  },
};

// ---------- Helpers ----------
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

async function pbkdf2(password, saltHex, iterations = PBKDF2_ITERATIONS) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}

function safeEqual(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return d === 0;
}

const SEC_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Robots-Tag": "noindex, nofollow",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};
const html = (body, status = 200, extra = {}) => new Response(body, { status, headers: { ...SEC_HEADERS, ...extra } });
const redirect = (to, extra = {}) => new Response(null, { status: 303, headers: { Location: to, "Cache-Control": "no-store", ...extra } });
const ip = (req) => req.headers.get("CF-Connecting-IP") || "unknown";

async function audit(env, actor, action, detail) {
  try {
    await env.HDB.prepare("INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)").bind(actor, action, String(detail).slice(0, 1000)).run();
  } catch (e) { console.error("audit failed", e); }
}

const readBody = async (req) => {
  try { return await req.formData(); } catch { return new FormData(); }
};
const notFound = (user, active) => {
  const r = page("Not found", user, active, "<h1>Not found</h1>");
  return new Response(r.body, { status: 404, headers: r.headers });
};

// ---------- Sessions ----------
function getCookie(req, name) {
  const m = (req.headers.get("Cookie") || "").match(new RegExp(`(?:^|;\\s*)${name}=([a-f0-9]{64})`));
  return m ? m[1] : null;
}

export async function currentUser(req, env) {
  const token = getCookie(req, COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT u.id, u.email FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1"
  ).bind(await sha256(token)).first();
  return row || null;
}

// Accept a change only when the browser says it came from this site.
const sameOrigin = (req) => {
  const site = req.headers.get("Sec-Fetch-Site");
  if (site) return site === "same-origin";
  const origin = req.headers.get("Origin");
  return Boolean(origin) && origin === new URL(req.url).origin;
};

// ---------- Layout ----------
const CSS = `
*{box-sizing:border-box}body{margin:0;font:15px/1.55 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f5f1;color:#14181f}
a{color:#7a5d0b}header{background:#050c1f;color:#e6ebf4;padding:12px 20px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
header b{font-family:Georgia,serif;font-weight:500;font-size:17px}header form{margin:0}header button{background:none;border:1px solid #c9a227;color:#e8c84a;padding:6px 12px;border-radius:6px;cursor:pointer}
.wrap{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 54px)}nav{background:#fff;border-right:1px solid #e4e2da;padding:16px 0}
nav h4{margin:14px 20px 4px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#8a8576}nav a{display:block;padding:6px 20px;text-decoration:none;color:#14181f}
nav a.on{background:#fbf5e3;border-left:3px solid #c9a227;padding-left:17px;font-weight:600}main{padding:24px;min-width:0}
h1{font:500 26px Georgia,serif;margin:0 0 16px}.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.btn{display:inline-block;background:#c9a227;color:#050c1f;border:0;padding:8px 14px;border-radius:6px;font-weight:600;text-decoration:none;cursor:pointer;font-size:14px}
.btn.ghost{background:#fff;border:1px solid #d8d4c6;color:#14181f}.btn.danger{background:#fff;border:1px solid #d9534f;color:#b52b27}
.tbl{overflow-x:auto;background:#fff;border:1px solid #e4e2da;border-radius:8px}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{padding:9px 12px;border-bottom:1px solid #eeece5;text-align:left;vertical-align:top;white-space:nowrap;max-width:320px;overflow:hidden;text-overflow:ellipsis}
th{background:#faf9f5;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#6b6656}tr:hover td{background:#fdfbf4}
.card{background:#fff;border:1px solid #e4e2da;border-radius:8px;padding:20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}.stat b{display:block;font:500 28px Georgia,serif}.stat{color:#6b6656}
form.edit{display:grid;gap:14px;max-width:640px}label{display:grid;gap:4px;font-size:13px;color:#4c4839}
input,select,textarea{font:inherit;padding:9px 11px;border:1px solid #d8d4c6;border-radius:6px;background:#fff;width:100%}textarea{min-height:110px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;background:#f1efe6;font-size:12px}.pill.new,.pill.open{background:#fff3cd}.pill.won,.pill.paid,.pill.done,.pill.active{background:#dff3e4}
.msg{padding:10px 14px;border-radius:6px;margin-bottom:14px}.msg.ok{background:#dff3e4}.msg.err{background:#fde2e1}
dl{display:grid;grid-template-columns:160px 1fr;gap:6px 16px;margin:0}dt{color:#6b6656}dd{margin:0;white-space:pre-wrap;word-break:break-word}
.login{max-width:380px;margin:10vh auto;padding:0 20px}.login .card{padding:28px}
@media(max-width:760px){.wrap{grid-template-columns:1fr}nav{border-right:0;border-bottom:1px solid #e4e2da;display:flex;flex-wrap:wrap;padding:8px}nav h4{display:none}nav a{padding:6px 10px}nav a.on{border-left:0;padding-left:10px}}`;

function page(title, user, active, body) {
  const groups = {};
  for (const [k, r] of Object.entries(RESOURCES)) (groups[r.group] ||= []).push([k, r]);
  const nav = `<a href="/admin" class="${active === "" ? "on" : ""}">Overview</a>` +
    Object.entries(groups).map(([g, items]) => `<h4>${esc(g)}</h4>` + items.map(([k, r]) => `<a href="/admin/${k}" class="${active === k ? "on" : ""}">${esc(r.title)}</a>`).join("")).join("") +
    `<h4>Account</h4><a href="/admin/password" class="${active === "password" ? "on" : ""}">Change password</a>`;
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} · Lunanele Admin</title><style>${CSS}</style></head><body>
<header><b>Lunanele Admin</b><div style="display:flex;gap:14px;align-items:center"><span style="color:#8a9ab5;font-size:13px">${esc(user.email)}</span><form method="post" action="/admin/logout"><button>Sign out</button></form></div></header>
<div class="wrap"><nav>${nav}</nav><main>${body}</main></div></body></html>`);
}

function loginPage(error = "") {
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Sign in · Lunanele Admin</title><style>${CSS}</style></head><body>
<div class="login"><h1>Lunanele Admin</h1><div class="card">${error ? `<div class="msg err">${esc(error)}</div>` : ""}
<form class="edit" method="post" action="/admin/login"><label>Email<input name="email" type="email" autocomplete="username" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="btn">Sign in</button></form></div></div></body></html>`, error ? 401 : 200);
}

const cell = (col, v) => {
  if (v === null || v === undefined || v === "") return '<span style="color:#b3ad9c">—</span>';
  if (col === "status") return `<span class="pill ${esc(v)}">${esc(v)}</span>`;
  if (/_zar$/.test(col) && typeof v === "number") return "R" + v.toLocaleString("en-ZA", { minimumFractionDigits: 2 });
  return esc(v);
};

async function refOptions(env, refKey) {
  const r = RESOURCES[refKey];
  const label = refKey === "people" ? "full_name" : "name";
  const { results } = await env[r.db].prepare(`SELECT ${r.pk} AS v, ${label} AS l FROM ${refKey} ORDER BY ${label}`).all();
  return results;
}

async function fieldInput(env, name, f, value) {
  const req = f.required ? " required" : "";
  const v = value ?? "";
  if (f.type === "select") {
    return `<select name="${name}"${req}>${f.required ? "" : '<option value="">—</option>'}${f.options.map((o) => `<option${String(v) === o ? " selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
  }
  if (f.type === "ref") {
    const opts = await refOptions(env, f.ref);
    return `<select name="${name}"${req}><option value="">—</option>${opts.map((o) => `<option value="${esc(o.v)}"${String(v) === String(o.v) ? " selected" : ""}>${esc(o.l)} (${esc(o.v)})</option>`).join("")}</select>`;
  }
  if (f.type === "textarea") return `<textarea name="${name}"${req}>${esc(v)}</textarea>`;
  const t = f.type === "number" ? 'number" step="any' : f.type === "date" ? "date" : f.type === "email" ? "email" : "text";
  return `<input type="${t}" name="${name}" value="${esc(v)}"${req}>`;
}

const label = (col) => col.replace(/_id$/, "").replace(/_zar$/, " (R)").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

function readForm(form, r, creating) {
  const data = {};
  for (const [col, f] of Object.entries(r.fields)) {
    if (!form.has(col)) continue;
    let v = String(form.get(col) ?? "").trim().slice(0, 4000);
    if (v === "") v = null;
    if (v !== null && f.type === "number") { v = Number(v); if (!Number.isFinite(v)) throw new Error(`${label(col)} must be a number`); }
    if (v !== null && f.type === "select" && !f.options.includes(String(v))) throw new Error(`Invalid ${label(col)}`);
    if (f.options && ["1", "0"].every((o) => f.options.includes(o)) && v !== null) v = Number(v);
    if (f.required && v === null) throw new Error(`${label(col)} is required`);
    data[col] = v;
  }
  if (creating && r.pkText) {
    const id = String(form.get("id") || "").trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{1,60}$/.test(id)) throw new Error("ID must be lowercase letters, numbers and dashes (e.g. lunanele-capital)");
    data[r.pk] = id;
  }
  return data;
}

// ---------- Views ----------
async function overview(env, user) {
  const q = async (db, sql) => (await env[db].prepare(sql).first())?.n ?? 0;
  const [enqNew, enqAll, leadsNew, customers, invOpen, compOpen, entities] = await Promise.all([
    q("DB", "SELECT count(*) n FROM enquiries WHERE status='new'"), q("DB", "SELECT count(*) n FROM enquiries"),
    q("DB", "SELECT count(*) n FROM leads WHERE status='new'"), q("DB", "SELECT count(*) n FROM customers WHERE status='active'"),
    q("DB", "SELECT count(*) n FROM invoices WHERE status='open'"),
    q("HDB", "SELECT count(*) n FROM compliance WHERE status<>'done'"), q("HDB", "SELECT count(*) n FROM entities"),
  ]);
  const { results: recent } = await env.DB.prepare("SELECT id, created_at, name, organisation, topic, status FROM enquiries ORDER BY created_at DESC LIMIT 8").all();
  const { results: due } = await env.HDB.prepare("SELECT id, item, entity_id, due_date, status FROM compliance WHERE status<>'done' ORDER BY due_date LIMIT 8").all();
  const stat = (n, l, href) => `<a class="card stat" href="${href}" style="text-decoration:none;color:inherit;margin:0"><b>${n}</b>${l}</a>`;
  const mini = (rows, cols, base) => rows.length ? `<div class="tbl"><table><tr>${cols.map((c) => `<th>${esc(label(c))}</th>`).join("")}</tr>${rows.map((x) => `<tr>${cols.map((c, i) => `<td>${i === 0 ? `<a href="/admin/${base}/${encodeURIComponent(x.id)}">${cell(c, x[c])}</a>` : cell(c, x[c])}</td>`).join("")}</tr>`).join("")}</table></div>` : '<p style="color:#8a8576">Nothing yet.</p>';
  return page("Overview", user, "", `<h1>Overview</h1>
<div class="grid" style="margin-bottom:24px">${stat(enqNew, `new enquiries <small>(${enqAll} total)</small>`, "/admin/enquiries")}${stat(leadsNew, "new leads", "/admin/leads")}${stat(customers, "active customers", "/admin/customers")}${stat(invOpen, "open invoices", "/admin/invoices")}${stat(compOpen, "open compliance items", "/admin/compliance")}${stat(entities, "group companies & trusts", "/admin/entities")}</div>
<h2 style="font:500 19px Georgia,serif">Latest enquiries</h2>${mini(recent, ["created_at", "name", "organisation", "topic", "status"], "enquiries")}
<h2 style="font:500 19px Georgia,serif;margin-top:24px">Compliance due</h2>${mini(due, ["due_date", "item", "entity_id", "status"], "compliance")}`);
}

async function listView(env, user, key, url, flash) {
  const r = RESOURCES[key];
  const qtext = (url.searchParams.get("q") || "").trim().slice(0, 100);
  const pageNo = Math.max(1, Number(url.searchParams.get("page")) || 1);
  const textCols = r.list.filter((c) => !/^(id|percentage|price_zar|total_zar|amount_zar|limit_zar|percent|active|quantity|customer_id)$/.test(c));
  const where = qtext ? `WHERE ${textCols.map((c) => `CAST(${c} AS TEXT) LIKE ?1`).join(" OR ")}` : "";
  const binds = qtext ? [`%${qtext}%`] : [];
  const { results } = await env[r.db].prepare(`SELECT ${[...new Set([r.pk, ...r.list])].join(", ")} FROM ${key} ${where} ORDER BY ${r.order} LIMIT 51 OFFSET ${(pageNo - 1) * 50}`).bind(...binds).all();
  const more = results.length > 50;
  const rows = results.slice(0, 50);
  const csvHref = `/admin/${key}.csv${qtext ? `?q=${encodeURIComponent(qtext)}` : ""}`;
  const pager = (pageNo > 1 ? `<a class="btn ghost" href="?q=${encodeURIComponent(qtext)}&page=${pageNo - 1}">← Newer</a>` : "") + (more ? `<a class="btn ghost" href="?q=${encodeURIComponent(qtext)}&page=${pageNo + 1}">Older →</a>` : "");
  return page(r.title, user, key, `<h1>${esc(r.title)}</h1>${flash}
<div class="bar"><form method="get" style="display:flex;gap:8px"><input name="q" value="${esc(qtext)}" placeholder="Search…" style="width:220px"><button class="btn ghost">Search</button></form>
${r.create !== false && !r.readonly ? `<a class="btn" href="/admin/${key}/new">+ Add</a>` : ""}<a class="btn ghost" href="${csvHref}">Download CSV</a></div>
<div class="tbl"><table><tr>${r.list.map((c) => `<th>${esc(label(c))}</th>`).join("")}</tr>
${rows.map((x) => `<tr>${r.list.map((c, i) => `<td>${i === 0 && !r.readonly ? `<a href="/admin/${key}/${encodeURIComponent(x[r.pk])}">${cell(c, x[c])}</a>` : cell(c, x[c])}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${r.list.length}" style="color:#8a8576">No records${qtext ? " match your search" : " yet"}.</td></tr>`}
</table></div><div class="bar" style="margin-top:12px">${pager}</div>`);
}

async function csvView(env, key, url) {
  const r = RESOURCES[key];
  const qtext = (url.searchParams.get("q") || "").trim().slice(0, 100);
  const cols = [...new Set([r.pk, ...r.list, ...(r.show || []), ...Object.keys(r.fields)])];
  const where = qtext ? `WHERE ${r.list.map((c) => `CAST(${c} AS TEXT) LIKE ?1`).join(" OR ")}` : "";
  const { results } = await env[r.db].prepare(`SELECT ${cols.join(", ")} FROM ${key} ${where} ORDER BY ${r.order} LIMIT 10000`).bind(...(qtext ? [`%${qtext}%`] : [])).all();
  const q = (v) => {
    let s = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@]/.test(s)) s = "'" + s; // stop spreadsheet formula injection
    return `"${s.replace(/"/g, '""')}"`;
  };
  const body = [cols.join(","), ...results.map((x) => cols.map((c) => q(x[c])).join(","))].join("\r\n");
  return new Response(body, { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="${key}-${new Date().toISOString().slice(0, 10)}.csv"`, "Cache-Control": "no-store" } });
}

async function formView(env, user, key, id, errorMsg = "", values = null, okMsg = "") {
  const r = RESOURCES[key];
  const creating = id === "new";
  let row = values || {};
  if (!creating && !values) {
    row = await env[r.db].prepare(`SELECT * FROM ${key} WHERE ${r.pk} = ?`).bind(id).first();
    if (!row) return page("Not found", user, key, `<h1>Not found</h1><p><a href="/admin/${key}">Back to ${esc(r.title)}</a></p>`);
  }
  const details = !creating && r.show ? `<div class="card"><dl>${r.show.map((c) => `<dt>${esc(label(c))}</dt><dd>${esc(row[c] ?? "—")}</dd>`).join("")}</dl>
${row.email ? `<p style="margin:14px 0 0"><a class="btn ghost" href="mailto:${esc(row.email)}">Reply by email</a></p>` : ""}</div>` : "";
  const inputs = [];
  if (creating && r.pkText) inputs.push(`<label>ID (short name, e.g. lunanele-capital)<input name="id" value="${esc(row.id ?? "")}" required pattern="[a-z0-9][a-z0-9\\-]{1,60}"></label>`);
  for (const [col, f] of Object.entries(r.fields)) inputs.push(`<label>${esc(label(col))}${f.required ? " *" : ""}${await fieldInput(env, col, f, row[col])}</label>`);
  const title = creating ? `New ${r.title.toLowerCase()}` : `${r.title} · ${id}`;
  const delForm = !creating && r.del !== false && !r.readonly
    ? `<form method="post" action="/admin/${key}/${encodeURIComponent(id)}/delete" class="card" style="max-width:640px"><label style="display:flex;gap:8px;align-items:center;font-size:14px"><input type="checkbox" name="confirm" value="yes" required style="width:auto"> I want to delete this record permanently</label><p style="margin:10px 0 0"><button class="btn danger">Delete</button></p></form>` : "";
  return page(title, user, key, `<p><a href="/admin/${key}">← ${esc(r.title)}</a></p><h1>${esc(title)}</h1>
${errorMsg ? `<div class="msg err">${esc(errorMsg)}</div>` : ""}${okMsg ? `<div class="msg ok">${esc(okMsg)}</div>` : ""}${details}
${inputs.length ? `<form class="edit card" method="post" action="/admin/${key}/${encodeURIComponent(id)}">${inputs.join("")}<div><button class="btn">${creating ? "Create" : "Save changes"}</button></div></form>` : ""}${delForm}`);
}

async function save(env, user, key, id, form) {
  const r = RESOURCES[key];
  const creating = id === "new";
  if (r.readonly || (creating && r.create === false)) throw new Error("Not allowed");
  const data = readForm(form, r, creating);
  const cols = Object.keys(data);
  if (creating) {
    await env[r.db].prepare(`INSERT INTO ${key} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`).bind(...cols.map((c) => data[c])).run();
    const newId = r.pkText ? data[r.pk] : (await env[r.db].prepare("SELECT last_insert_rowid() AS id").first()).id;
    await audit(env, user.email, `create ${key}`, `${newId}: ${JSON.stringify(data)}`);
    return newId;
  }
  if (!cols.length) return id;
  const sets = cols.map((c) => `${c} = ?`);
  if (r.touch) sets.push(`${r.touch} = datetime('now')`);
  const res = await env[r.db].prepare(`UPDATE ${key} SET ${sets.join(", ")} WHERE ${r.pk} = ?`).bind(...cols.map((c) => data[c]), id).run();
  if (!res.meta?.changes) throw new Error("Record not found");
  await audit(env, user.email, `update ${key}`, `${id}: ${JSON.stringify(data)}`);
  return id;
}

// ---------- Router ----------
export async function handleAdmin(req, env) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/admin";
  const method = req.method;

  if (url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) {
    return redirect(url.href.replace(/^http:/, "https:"));
  }
  if (method === "POST" && !sameOrigin(req)) return html("Blocked: cross-site request", 403);

  // Sign in
  if (path === "/admin/login") {
    if (method !== "POST") return redirect("/admin");
    const addr = ip(req);
    const fails = (await env.DB.prepare("SELECT count(*) n FROM admin_login_attempts WHERE ip = ? AND at > datetime('now','-15 minutes')").bind(addr).first())?.n ?? 0;
    if (fails >= MAX_FAILS) return loginPage("Too many attempts. Wait 15 minutes and try again.");
    const form = await readBody(req);
    const email = String(form.get("email") || "").trim().toLowerCase();
    const password = String(form.get("password") || "");
    const u = await env.DB.prepare("SELECT id, email, pw_hash, pw_salt, iterations FROM admin_users WHERE email = ? AND active = 1").bind(email).first();
    const ok = u && safeEqual(await pbkdf2(password, u.pw_salt, u.iterations), u.pw_hash);
    if (!ok) {
      await env.DB.prepare("INSERT INTO admin_login_attempts (ip, email) VALUES (?, ?)").bind(addr, email.slice(0, 200)).run();
      await audit(env, email || "unknown", "login failed", addr);
      return loginPage("Wrong email or password.");
    }
    const token = randomHex(32);
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO admin_sessions (token_hash, user_id, ip, expires_at) VALUES (?, ?, ?, datetime('now', '+${SESSION_HOURS} hours'))`).bind(await sha256(token), u.id, addr),
      env.DB.prepare("UPDATE admin_users SET last_login = datetime('now') WHERE id = ?").bind(u.id),
      env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at < datetime('now')"),
      env.DB.prepare("DELETE FROM admin_login_attempts WHERE at < datetime('now','-1 day')"),
    ]);
    await audit(env, u.email, "login", addr);
    return redirect("/admin", { "Set-Cookie": `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}` });
  }

  const user = await currentUser(req, env);
  if (!user) return method === "GET" ? loginPage() : redirect("/admin");

  if (path === "/admin/logout" && method === "POST") {
    const token = getCookie(req, COOKIE);
    if (token) await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    await audit(env, user.email, "logout", "");
    return redirect("/admin", { "Set-Cookie": `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0` });
  }

  if (path === "/admin") return overview(env, user);

  if (path === "/admin/password") {
    const body = (msg) => page("Change password", user, "password", `<h1>Change password</h1>${msg}
<form class="edit card" method="post"><label>Current password<input type="password" name="current" autocomplete="current-password" required></label>
<label>New password (at least 12 characters)<input type="password" name="next" autocomplete="new-password" minlength="12" required></label>
<label>New password again<input type="password" name="again" autocomplete="new-password" minlength="12" required></label><div><button class="btn">Update password</button></div></form>`);
    if (method !== "POST") return body("");
    const form = await readBody(req);
    const u = await env.DB.prepare("SELECT pw_hash, pw_salt, iterations FROM admin_users WHERE id = ?").bind(user.id).first();
    const next = String(form.get("next") || "");
    if (!safeEqual(await pbkdf2(String(form.get("current") || ""), u.pw_salt, u.iterations), u.pw_hash)) return body('<div class="msg err">Current password is wrong.</div>');
    if (next.length < 12) return body('<div class="msg err">New password must be at least 12 characters.</div>');
    if (next !== String(form.get("again") || "")) return body('<div class="msg err">The new passwords don\'t match.</div>');
    const salt = randomHex(16);
    const token = getCookie(req, COOKIE);
    await env.DB.batch([
      env.DB.prepare("UPDATE admin_users SET pw_hash = ?, pw_salt = ?, iterations = ? WHERE id = ?").bind(await pbkdf2(next, salt), salt, PBKDF2_ITERATIONS, user.id),
      env.DB.prepare("DELETE FROM admin_sessions WHERE user_id = ? AND token_hash <> ?").bind(user.id, await sha256(token)),
    ]);
    await audit(env, user.email, "password changed", "other sessions signed out");
    return body('<div class="msg ok">Password updated. Any other signed-in devices have been signed out.</div>');
  }

  const m = path.match(/^\/admin\/([a-z_]+)(\.csv)?(?:\/([^/]+))?(\/delete)?$/);
  if (!m || !RESOURCES[m[1]]) return notFound(user, "");
  const [, key, csv, rawId, del] = m;
  const r = RESOURCES[key];
  const id = rawId ? decodeURIComponent(rawId) : null;

  if (csv && method === "GET" && !id) return csvView(env, key, url);
  if (!id && method === "GET") {
    const flash = url.searchParams.get("ok") ? `<div class="msg ok">${esc(url.searchParams.get("ok"))}</div>` : "";
    return listView(env, user, key, url, flash);
  }
  if (id && !del && method === "GET") {
    if (r.readonly || (id === "new" && r.create === false)) return redirect(`/admin/${key}`);
    return formView(env, user, key, id, "", null, url.searchParams.get("saved") ? "Saved." : "");
  }
  if (id && del && method === "POST") {
    if (r.del === false || r.readonly) return html("Not allowed", 403);
    const form = await readBody(req);
    if (form.get("confirm") !== "yes") return formView(env, user, key, id, "Tick the box to confirm the delete.");
    try {
      await env[r.db].prepare(`DELETE FROM ${key} WHERE ${r.pk} = ?`).bind(id).run();
    } catch (e) {
      return formView(env, user, key, id, "Can't delete: other records still point to this one.");
    }
    await audit(env, user.email, `delete ${key}`, id);
    return redirect(`/admin/${key}?ok=${encodeURIComponent("Deleted.")}`);
  }
  if (id && !del && method === "POST") {
    const form = await readBody(req);
    try {
      const newId = await save(env, user, key, id, form);
      return redirect(`/admin/${key}/${encodeURIComponent(newId)}?saved=1`);
    } catch (e) {
      const msg = /UNIQUE|PRIMARY KEY/.test(e.message) ? "That ID is already used." : /FOREIGN KEY|CHECK/.test(e.message) ? "That value isn't allowed here." : e.message;
      const values = Object.fromEntries(form.entries());
      return formView(env, user, key, id, msg, values);
    }
  }
  return html("Method not allowed", 405);
}
