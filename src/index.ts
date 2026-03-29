import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Env = {
  DB: D1Database;
  CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  EMAIL_SENDER: Fetcher;
  ECHO_API_KEY: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  ANALYTICS: AnalyticsEngineDataset;
};

const app = new Hono<{ Bindings: Env }>();
// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

app.use('*', cors());

function uid(): string { return crypto.randomUUID(); }
function sanitize(s: unknown, max = 5000): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max);
}
function sanitizeBody(b: Record<string, unknown>): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(b)) o[k] = typeof v === 'string' ? sanitize(v) : v;
  return o;
}
function tid(c: any): string { return sanitize(c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '', 100); }
function json(c: any, d: unknown, s = 200) { return c.json(d, s); }

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-email-marketing', version: '2.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}


// === STRIPE HELPERS ===
const PLAN_LIMITS: Record<string, { contacts: number; emails_month: number; price_cents: number; name: string }> = {
  free:       { contacts: 500,       emails_month: 1000,       price_cents: 0,    name: 'Free' },
  pro:        { contacts: 5000,      emails_month: 50000,      price_cents: 2900, name: 'Pro' },
  enterprise: { contacts: 999999999, emails_month: 999999999,  price_cents: 9900, name: 'Enterprise' },
};

async function verifyStripeSignature(body: string, sigHeader: string, secret: string): Promise<boolean> {
  const parts = sigHeader.split(',');
  let timestamp = '';
  const signatures: string[] = [];
  for (const p of parts) {
    const [k, v] = p.split('=');
    if (k === 't') timestamp = v;
    if (k === 'v1') signatures.push(v);
  }
  if (!timestamp || signatures.length === 0) return false;
  // Reject events older than 5 minutes (replay protection)
  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp));
  if (age > 300) return false;
  const payload = `${timestamp}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  // Constant-time compare
  if (expected.length !== signatures[0].length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signatures[0].charCodeAt(i);
  return diff === 0;
}

async function stripeAPI(env: Env, path: string, method: string, params?: Record<string, string>): Promise<any> {
  const opts: RequestInit = {
    method,
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  };
  if (params && (method === 'POST' || method === 'PUT')) {
    opts.body = new URLSearchParams(params).toString();
  }
  const url = method === 'GET' && params
    ? `https://api.stripe.com/v1${path}?${new URLSearchParams(params).toString()}`
    : `https://api.stripe.com/v1${path}`;
  const resp = await fetch(url, opts);
  return resp.json();
}

interface RLState { c: number; t: number }
// CORS headers (auto-added by Evolution Engine)
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Echo-API-Key',
};

async function rateLimit(env: Env, key: string, max: number, windowSec = 60): Promise<boolean> {
  const k = `rl:${key}`;
  const now = Date.now();
  const raw = await env.CACHE.get(k);
  let st: RLState = raw ? JSON.parse(raw) : { c: 0, t: now };
  const elapsed = (now - st.t) / 1000;
  const decay = Math.floor(elapsed * (max / windowSec));
  st.c = Math.max(0, st.c - decay);
  st.t = now;
  if (st.c >= max) return false;
  st.c++;
  await env.CACHE.put(k, JSON.stringify(st), { expirationTtl: windowSec * 2 });
  return true;
}

// Auth
app.use('*', async (c, next) => {
  const path = c.req.path;
  if (path === '/health' || path === '/status' || path === '/subscribe' || path.startsWith('/track/') || path.startsWith('/unsubscribe/') || path === '/webhooks/stripe') return next();
  if (c.req.method === 'GET') return next();
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  if (!key || key !== c.env.ECHO_API_KEY) return json(c, { error: 'Unauthorized' }, 401);
  return next();
});

// Rate limiting
app.use('*', async (c, next) => {
  const path = c.req.path;
  if (path === '/health' || path === '/status') return next();
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const max = c.req.method === 'GET' ? 200 : 60;
  if (!await rateLimit(c.env, `${ip}:${c.req.method}`, max)) return json(c, { error: 'Rate limited' }, 429);
  return next();
});

// Health
app.get('/', (c) => json(c, { service: 'echo-email-marketing', version: '2.0.0', status: 'operational' }));
app.get('/health', (c) => json(c, { status: 'ok', service: 'echo-email-marketing', version: '2.0.0', timestamp: new Date().toISOString(), stripe: !!c.env.STRIPE_SECRET_KEY, plans: Object.keys(PLAN_LIMITS) }));
app.get('/status', (c) => json(c, { status: 'operational', service: 'echo-email-marketing', version: '2.0.0' }));

// === PUBLIC SUBSCRIBE (no auth — for website signup forms) ===
app.post('/subscribe', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  const email = sanitize(b.email || '', 320).trim().toLowerCase();
  if (!email || !email.includes('@') || !email.includes('.')) return json(c, { error: 'Invalid email' }, 400);
  const tenantId = sanitize(b.tenant_id || '', 100);
  const listId = sanitize(b.list_id || '', 100);
  if (!tenantId) return json(c, { error: 'tenant_id required' }, 400);
  // Rate limit: 5 subscribe attempts per IP per 5 minutes
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  if (!await rateLimit(c.env, `subscribe:${ip}`, 5, 300)) return json(c, { error: 'Too many attempts — try again later' }, 429);
  // Check tenant exists
  const tenant = await c.env.DB.prepare('SELECT id, max_contacts FROM tenants WHERE id=?').bind(tenantId).first<any>();
  if (!tenant) return json(c, { error: 'Invalid tenant' }, 400);
  // Check contact limit
  const cnt = await c.env.DB.prepare('SELECT COUNT(*) as c FROM contacts WHERE tenant_id=?').bind(tenantId).first<any>();
  if (cnt && cnt.c >= tenant.max_contacts) return json(c, { error: 'List is full' }, 403);
  // Upsert contact (don't fail on duplicate email)
  let contactId: string;
  const existing = await c.env.DB.prepare('SELECT id FROM contacts WHERE tenant_id=? AND email=?').bind(tenantId, email).first<any>();
  if (existing) {
    contactId = existing.id;
  } else {
    contactId = uid();
    const tags = JSON.stringify(b.tags ? (typeof b.tags === 'string' ? b.tags.split(',').map((t: string) => t.trim()) : b.tags) : ['newsletter']);
    await c.env.DB.prepare('INSERT INTO contacts (id,tenant_id,email,first_name,last_name,tags,custom_fields) VALUES (?,?,?,?,?,?,?)')
      .bind(contactId, tenantId, email, sanitize(b.name || b.first_name || '', 200) || null, sanitize(b.last_name || '', 200) || null, tags, JSON.stringify({ source: sanitize(b.source || 'website', 100) }))
      .run();
    slog('info', 'New subscriber', { email, tenant_id: tenantId, source: b.source });
  }
  // Add to list if specified
  if (listId) {
    try {
      await c.env.DB.prepare('INSERT OR IGNORE INTO list_members (id,list_id,contact_id) VALUES (?,?,?)').bind(uid(), listId, contactId).run();
      await c.env.DB.prepare('UPDATE lists SET contact_count=(SELECT COUNT(*) FROM list_members WHERE list_id=?) WHERE id=?').bind(listId, listId).run();
    } catch {}
  }
  return json(c, { ok: true, id: contactId }, 201);
});

// === TENANTS ===
app.post('/tenants', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  const id = uid();
  await c.env.DB.prepare('INSERT INTO tenants (id,name,email,plan,max_contacts,max_campaigns_month,sender_name,sender_email,reply_to) VALUES (?,?,?,?,?,?,?,?,?)').bind(id, b.name, b.email || null, b.plan || 'free', b.max_contacts || 500, b.max_campaigns_month || 10, b.sender_name || b.name, b.sender_email || b.email || null, b.reply_to || null).run();
  return json(c, { id }, 201);
});
app.get('/tenants/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
  return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
});

// === CONTACTS ===
app.get('/contacts', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const search = c.req.query('search');
  const status = c.req.query('status');
  const tag = c.req.query('tag');
  let q = 'SELECT * FROM contacts WHERE tenant_id=?';
  const params: string[] = [t];
  if (search) { q += ' AND (email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (status) { q += ' AND status=?'; params.push(status); }
  if (tag) { q += ' AND tags LIKE ?'; params.push(`%"${tag}"%`); }
  q += ' ORDER BY created_at DESC LIMIT 100';
  const r = await c.env.DB.prepare(q).bind(...params).all();
  return json(c, { contacts: r.results });
});
app.post('/contacts', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = sanitizeBody(await c.req.json()) as any;
  const tenant = await c.env.DB.prepare('SELECT max_contacts FROM tenants WHERE id=?').bind(t).first<any>();
  if (tenant) {
    const cnt = await c.env.DB.prepare('SELECT COUNT(*) as c FROM contacts WHERE tenant_id=?').bind(t).first<any>();
    if (cnt && cnt.c >= tenant.max_contacts) return json(c, { error: 'Contact limit reached' }, 403);
  }
  const id = uid();
  await c.env.DB.prepare('INSERT INTO contacts (id,tenant_id,email,first_name,last_name,phone,company,tags,custom_fields) VALUES (?,?,?,?,?,?,?,?,?)').bind(id, t, b.email, b.first_name || null, b.last_name || null, b.phone || null, b.company || null, JSON.stringify(b.tags || []), JSON.stringify(b.custom_fields || {})).run();
  return json(c, { id }, 201);
});
app.post('/contacts/import', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = await c.req.json() as any;
  const contacts = b.contacts || [];
  let imported = 0;
  for (const ct of contacts.slice(0, 1000)) {
    try {
      await c.env.DB.prepare('INSERT OR IGNORE INTO contacts (id,tenant_id,email,first_name,last_name,tags) VALUES (?,?,?,?,?,?)').bind(uid(), t, ct.email, ct.first_name || null, ct.last_name || null, JSON.stringify(ct.tags || [])).run();
      imported++;
    } catch {}
  }
  return json(c, { imported, total: contacts.length });
});
app.put('/contacts/:id', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  await c.env.DB.prepare('UPDATE contacts SET first_name=COALESCE(?,first_name),last_name=COALESCE(?,last_name),phone=COALESCE(?,phone),company=COALESCE(?,company),tags=COALESCE(?,tags),custom_fields=COALESCE(?,custom_fields) WHERE id=?').bind(b.first_name || null, b.last_name || null, b.phone || null, b.company || null, b.tags ? JSON.stringify(b.tags) : null, b.custom_fields ? JSON.stringify(b.custom_fields) : null, c.req.param('id')).run();
  return json(c, { updated: true });
});

// === LISTS ===
app.get('/lists', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const r = await c.env.DB.prepare('SELECT * FROM lists WHERE tenant_id=? ORDER BY name').bind(t).all();
  return json(c, { lists: r.results });
});
app.post('/lists', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = sanitizeBody(await c.req.json()) as any;
  const id = uid();
  await c.env.DB.prepare('INSERT INTO lists (id,tenant_id,name,description) VALUES (?,?,?,?)').bind(id, t, b.name, b.description || null).run();
  return json(c, { id }, 201);
});
app.post('/lists/:lid/add', async (c) => {
  const b = await c.req.json() as any;
  const contactIds = b.contact_ids || [];
  let added = 0;
  for (const cid of contactIds) {
    try {
      await c.env.DB.prepare('INSERT OR IGNORE INTO list_members (id,list_id,contact_id) VALUES (?,?,?)').bind(uid(), c.req.param('lid'), cid).run();
      added++;
    } catch {}
  }
  await c.env.DB.prepare('UPDATE lists SET contact_count=(SELECT COUNT(*) FROM list_members WHERE list_id=?) WHERE id=?').bind(c.req.param('lid'), c.req.param('lid')).run();
  return json(c, { added });
});
app.post('/lists/:lid/remove', async (c) => {
  const b = await c.req.json() as any;
  const contactIds = b.contact_ids || [];
  for (const cid of contactIds) {
    await c.env.DB.prepare('DELETE FROM list_members WHERE list_id=? AND contact_id=?').bind(c.req.param('lid'), cid).run();
  }
  await c.env.DB.prepare('UPDATE lists SET contact_count=(SELECT COUNT(*) FROM list_members WHERE list_id=?) WHERE id=?').bind(c.req.param('lid'), c.req.param('lid')).run();
  return json(c, { removed: contactIds.length });
});
app.get('/lists/:lid/contacts', async (c) => {
  const r = await c.env.DB.prepare('SELECT c.* FROM contacts c JOIN list_members lm ON c.id=lm.contact_id WHERE lm.list_id=? ORDER BY c.email').bind(c.req.param('lid')).all();
  return json(c, { contacts: r.results });
});

// === TEMPLATES ===
app.get('/templates', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const r = await c.env.DB.prepare('SELECT * FROM templates WHERE tenant_id=? OR is_global=1 ORDER BY use_count DESC').bind(t).all();
  return json(c, { templates: r.results });
});
app.post('/templates', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = sanitizeBody(await c.req.json()) as any;
  const id = uid();
  await c.env.DB.prepare('INSERT INTO templates (id,tenant_id,name,subject,html_content,text_content,category,variables) VALUES (?,?,?,?,?,?,?,?)').bind(id, t, b.name, b.subject || null, b.html_content || null, b.text_content || null, b.category || 'general', JSON.stringify(b.variables || [])).run();
  return json(c, { id }, 201);
});

// === CAMPAIGNS ===
app.get('/campaigns', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const status = c.req.query('status');
  let q = 'SELECT * FROM campaigns WHERE tenant_id=?';
  const params: string[] = [t];
  if (status) { q += ' AND status=?'; params.push(status); }
  q += ' ORDER BY created_at DESC';
  const r = await c.env.DB.prepare(q).bind(...params).all();
  return json(c, { campaigns: r.results });
});
app.get('/campaigns/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM campaigns WHERE id=?').bind(c.req.param('id')).first();
  return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
});
app.post('/campaigns', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = sanitizeBody(await c.req.json()) as any;
  const id = uid();
  const tenant = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(t).first<any>();
  await c.env.DB.prepare('INSERT INTO campaigns (id,tenant_id,name,subject,preview_text,from_name,from_email,reply_to,html_content,text_content,template_id,list_id,type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, t, b.name, b.subject, b.preview_text || null, b.from_name || tenant?.sender_name || null, b.from_email || tenant?.sender_email || null, b.reply_to || tenant?.reply_to || null, b.html_content || null, b.text_content || null, b.template_id || null, b.list_id || null, b.type || 'regular').run();
  if (b.template_id) await c.env.DB.prepare('UPDATE templates SET use_count=use_count+1 WHERE id=?').bind(b.template_id).run();
  return json(c, { id }, 201);
});
app.put('/campaigns/:id', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  await c.env.DB.prepare('UPDATE campaigns SET name=COALESCE(?,name),subject=COALESCE(?,subject),preview_text=COALESCE(?,preview_text),html_content=COALESCE(?,html_content),text_content=COALESCE(?,text_content),list_id=COALESCE(?,list_id),updated_at=datetime(\'now\') WHERE id=?').bind(b.name || null, b.subject || null, b.preview_text || null, b.html_content || null, b.text_content || null, b.list_id || null, c.req.param('id')).run();
  return json(c, { updated: true });
});
app.post('/campaigns/:id/schedule', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  await c.env.DB.prepare("UPDATE campaigns SET status='scheduled',scheduled_at=?,updated_at=datetime('now') WHERE id=?").bind(b.scheduled_at, c.req.param('id')).run();
  return json(c, { scheduled: true });
});
app.post('/campaigns/:id/send', async (c) => {
  const campaign = await c.env.DB.prepare('SELECT * FROM campaigns WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!campaign) return json(c, { error: 'Campaign not found' }, 404);
  if (!campaign.list_id) return json(c, { error: 'No list assigned' }, 400);
  const contacts = await c.env.DB.prepare("SELECT c.* FROM contacts c JOIN list_members lm ON c.id=lm.contact_id WHERE lm.list_id=? AND c.status='active'").bind(campaign.list_id).all();
  const total = contacts.results?.length || 0;
  await c.env.DB.prepare("UPDATE campaigns SET status='sending',total_sent=?,sent_at=datetime('now'),updated_at=datetime('now') WHERE id=?").bind(total, c.req.param('id')).run();
  // In production, this would queue emails via EMAIL_SENDER service binding
  await c.env.DB.prepare("UPDATE campaigns SET status='sent',total_delivered=?,updated_at=datetime('now') WHERE id=?").bind(total, c.req.param('id')).run();
  return json(c, { sent: true, total_recipients: total });
});
app.post('/campaigns/:id/ab-test', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  const parent = await c.env.DB.prepare('SELECT * FROM campaigns WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!parent) return json(c, { error: 'Campaign not found' }, 404);
  const variantId = uid();
  await c.env.DB.prepare('INSERT INTO campaigns (id,tenant_id,name,subject,preview_text,from_name,from_email,html_content,text_content,list_id,type,ab_variant,ab_parent_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(variantId, parent.tenant_id, `${parent.name} (Variant B)`, b.subject || parent.subject, b.preview_text || parent.preview_text, parent.from_name, parent.from_email, b.html_content || parent.html_content, b.text_content || parent.text_content, parent.list_id, 'ab_test', 'B', c.req.param('id')).run();
  await c.env.DB.prepare("UPDATE campaigns SET type='ab_test',ab_variant='A' WHERE id=?").bind(c.req.param('id')).run();
  return json(c, { variant_id: variantId }, 201);
});

// === TRACKING (public, no auth) ===
app.get('/track/open/:campaignId/:contactId', async (c) => {
  const cid = c.req.param('campaignId');
  const ctid = c.req.param('contactId');
  await c.env.DB.prepare('INSERT INTO campaign_events (id,campaign_id,contact_id,tenant_id,event_type,ip_address,user_agent) VALUES (?,?,?,(SELECT tenant_id FROM campaigns WHERE id=?),?,?,?)').bind(uid(), cid, ctid, cid, 'open', c.req.header('CF-Connecting-IP') || '', c.req.header('User-Agent') || '').run();
  await c.env.DB.prepare('UPDATE campaigns SET total_opened=total_opened+1,open_rate=CAST(total_opened+1 AS REAL)/CAST(CASE WHEN total_sent>0 THEN total_sent ELSE 1 END AS REAL)*100 WHERE id=?').bind(cid).run();
  await c.env.DB.prepare("UPDATE contacts SET last_opened_at=datetime('now') WHERE id=?").bind(ctid).run();
  // Return 1x1 transparent pixel
  return new Response(Uint8Array.from(atob('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'), c => c.charCodeAt(0)), { headers: { 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' } });
});
app.get('/track/click/:campaignId/:contactId', async (c) => {
  const cid = c.req.param('campaignId');
  const ctid = c.req.param('contactId');
  const url = c.req.query('url') || '/';
  await c.env.DB.prepare('INSERT INTO campaign_events (id,campaign_id,contact_id,tenant_id,event_type,link_url,ip_address,user_agent) VALUES (?,?,?,(SELECT tenant_id FROM campaigns WHERE id=?),?,?,?,?)').bind(uid(), cid, ctid, cid, 'click', url, c.req.header('CF-Connecting-IP') || '', c.req.header('User-Agent') || '').run();
  await c.env.DB.prepare('UPDATE campaigns SET total_clicked=total_clicked+1,click_rate=CAST(total_clicked+1 AS REAL)/CAST(CASE WHEN total_sent>0 THEN total_sent ELSE 1 END AS REAL)*100 WHERE id=?').bind(cid).run();
  await c.env.DB.prepare("UPDATE contacts SET last_clicked_at=datetime('now') WHERE id=?").bind(ctid).run();
  return c.redirect(url, 302);
});

// === UNSUBSCRIBE (public) ===
app.get('/unsubscribe/:contactId', async (c) => {
  const ctid = c.req.param('contactId');
  const campId = c.req.query('campaign_id');
  await c.env.DB.prepare("UPDATE contacts SET status='unsubscribed',unsubscribed_at=datetime('now') WHERE id=?").bind(ctid).run();
  if (campId) {
    await c.env.DB.prepare('UPDATE campaigns SET total_unsubscribed=total_unsubscribed+1 WHERE id=?').bind(campId).run();
    await c.env.DB.prepare('INSERT INTO unsubscribes (id,tenant_id,contact_id,campaign_id) VALUES (?,(SELECT tenant_id FROM contacts WHERE id=?),?,?)').bind(uid(), ctid, ctid, campId).run();
  }
  return new Response('<html><body style="font-family:sans-serif;text-align:center;padding:60px"><h2>Unsubscribed</h2><p>You have been successfully unsubscribed.</p></body></html>', { headers: { 'Content-Type': 'text/html' } });
});

// === AUTOMATIONS ===
app.get('/automations', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const r = await c.env.DB.prepare('SELECT * FROM automations WHERE tenant_id=? ORDER BY created_at DESC').bind(t).all();
  return json(c, { automations: r.results });
});
app.post('/automations', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = sanitizeBody(await c.req.json()) as any;
  const id = uid();
  await c.env.DB.prepare('INSERT INTO automations (id,tenant_id,name,description,trigger_type,trigger_config,steps_json) VALUES (?,?,?,?,?,?,?)').bind(id, t, b.name, b.description || null, b.trigger_type, JSON.stringify(b.trigger_config || {}), JSON.stringify(b.steps || [])).run();
  return json(c, { id }, 201);
});
app.post('/automations/:id/activate', async (c) => {
  await c.env.DB.prepare("UPDATE automations SET status='active' WHERE id=?").bind(c.req.param('id')).run();
  return json(c, { activated: true });
});
app.post('/automations/:id/deactivate', async (c) => {
  await c.env.DB.prepare("UPDATE automations SET status='inactive' WHERE id=?").bind(c.req.param('id')).run();
  return json(c, { deactivated: true });
});
app.post('/automations/:id/enroll', async (c) => {
  const b = await c.req.json() as any;
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const id = uid();
  await c.env.DB.prepare('INSERT INTO automation_enrollments (id,automation_id,contact_id,tenant_id) VALUES (?,?,?,?)').bind(id, c.req.param('id'), b.contact_id, t).run();
  await c.env.DB.prepare('UPDATE automations SET enrolled_count=enrolled_count+1 WHERE id=?').bind(c.req.param('id')).run();
  return json(c, { id }, 201);
});

// === ANALYTICS ===
app.get('/analytics/overview', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const [contacts, active, campaigns, sent, avgOpen, avgClick] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as c FROM contacts WHERE tenant_id=?').bind(t).first<any>(),
    c.env.DB.prepare("SELECT COUNT(*) as c FROM contacts WHERE tenant_id=? AND status='active'").bind(t).first<any>(),
    c.env.DB.prepare('SELECT COUNT(*) as c FROM campaigns WHERE tenant_id=?').bind(t).first<any>(),
    c.env.DB.prepare("SELECT COUNT(*) as c FROM campaigns WHERE tenant_id=? AND status='sent'").bind(t).first<any>(),
    c.env.DB.prepare("SELECT AVG(open_rate) as avg FROM campaigns WHERE tenant_id=? AND status='sent'").bind(t).first<any>(),
    c.env.DB.prepare("SELECT AVG(click_rate) as avg FROM campaigns WHERE tenant_id=? AND status='sent'").bind(t).first<any>(),
  ]);
  return json(c, {
    total_contacts: contacts?.c || 0,
    active_contacts: active?.c || 0,
    total_campaigns: campaigns?.c || 0,
    sent_campaigns: sent?.c || 0,
    avg_open_rate: Math.round((avgOpen?.avg || 0) * 100) / 100,
    avg_click_rate: Math.round((avgClick?.avg || 0) * 100) / 100,
  });
});
app.get('/analytics/campaign/:id', async (c) => {
  const campaign = await c.env.DB.prepare('SELECT * FROM campaigns WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!campaign) return json(c, { error: 'Not found' }, 404);
  const events = await c.env.DB.prepare('SELECT event_type, COUNT(*) as count FROM campaign_events WHERE campaign_id=? GROUP BY event_type').bind(c.req.param('id')).all();
  const topLinks = await c.env.DB.prepare("SELECT link_url, COUNT(*) as clicks FROM campaign_events WHERE campaign_id=? AND event_type='click' GROUP BY link_url ORDER BY clicks DESC LIMIT 10").bind(c.req.param('id')).all();
  return json(c, { campaign, events: events.results, top_links: topLinks.results });
});
app.get('/analytics/growth', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const r = await c.env.DB.prepare("SELECT DATE(subscribed_at) as day, COUNT(*) as new_contacts FROM contacts WHERE tenant_id=? AND subscribed_at > datetime('now','-30 days') GROUP BY day ORDER BY day").bind(t).all();
  return json(c, { growth: r.results });
});

// === STRIPE WEBHOOK (public, signature-verified) ===
app.post('/webhooks/stripe', async (c) => {
  const sig = c.req.header('Stripe-Signature');
  if (!sig || !c.env.STRIPE_WEBHOOK_SECRET) return json(c, { error: 'Missing signature or webhook secret' }, 400);
  const body = await c.req.text();
  const valid = await verifyStripeSignature(body, sig, c.env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    slog('warn', 'Stripe webhook signature verification failed');
    return json(c, { error: 'Invalid signature' }, 401);
  }
  const event = JSON.parse(body);
  slog('info', 'Stripe webhook received', { type: event.type, id: event.id });

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const tenantId = session.metadata?.tenant_id;
    const plan = session.metadata?.plan;
    const customerId = session.customer;
    if (tenantId && plan && PLAN_LIMITS[plan]) {
      const limits = PLAN_LIMITS[plan];
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      await c.env.DB.prepare(
        "UPDATE tenants SET plan=?, max_contacts=?, stripe_customer_id=?, plan_tier=?, plan_expires_at=?, updated_at=datetime('now') WHERE id=?"
      ).bind(plan, limits.contacts, customerId, plan, expiresAt, tenantId).run();
      slog('info', 'Plan upgraded via Stripe checkout', { tenant_id: tenantId, plan, customer_id: customerId });
    }
  } else if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const customerId = sub.customer;
    const tenant = await c.env.DB.prepare('SELECT id FROM tenants WHERE stripe_customer_id=?').bind(customerId).first<any>();
    if (tenant) {
      const free = PLAN_LIMITS.free;
      await c.env.DB.prepare(
        "UPDATE tenants SET plan='free', max_contacts=?, plan_tier='free', plan_expires_at=NULL, updated_at=datetime('now') WHERE id=?"
      ).bind(free.contacts, tenant.id).run();
      slog('info', 'Subscription cancelled, downgraded to free', { tenant_id: tenant.id, customer_id: customerId });
    }
  }

  return json(c, { received: true });
});

// === PLAN MANAGEMENT ===
app.get('/plans', async (c) => {
  const t = tid(c);
  if (!t) {
    // Return plan catalog
    return json(c, {
      plans: Object.entries(PLAN_LIMITS).map(([k, v]) => ({
        id: k, name: v.name, contacts: v.contacts, emails_month: v.emails_month,
        price: v.price_cents === 0 ? 'Free' : `$${v.price_cents / 100}/mo`,
      })),
    });
  }
  const tenant = await c.env.DB.prepare('SELECT id, name, plan, max_contacts, stripe_customer_id, plan_tier, plan_expires_at FROM tenants WHERE id=?').bind(t).first<any>();
  if (!tenant) return json(c, { error: 'Tenant not found' }, 404);
  const contactCount = await c.env.DB.prepare('SELECT COUNT(*) as c FROM contacts WHERE tenant_id=?').bind(t).first<any>();
  const currentPlan = PLAN_LIMITS[tenant.plan || 'free'];
  return json(c, {
    tenant_id: tenant.id,
    tenant_name: tenant.name,
    current_plan: tenant.plan || 'free',
    plan_name: currentPlan.name,
    contacts_used: contactCount?.c || 0,
    contacts_limit: currentPlan.contacts,
    emails_month_limit: currentPlan.emails_month,
    stripe_customer_id: tenant.stripe_customer_id || null,
    plan_expires_at: tenant.plan_expires_at || null,
    available_upgrades: Object.entries(PLAN_LIMITS)
      .filter(([k]) => PLAN_LIMITS[k].price_cents > (currentPlan?.price_cents || 0))
      .map(([k, v]) => ({ id: k, name: v.name, price: `$${v.price_cents / 100}/mo` })),
  });
});

app.post('/plans/upgrade', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return json(c, { error: 'Stripe not configured' }, 503);
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  const b = await c.req.json() as any;
  const plan = sanitize(b.plan, 20);
  if (!plan || !PLAN_LIMITS[plan] || plan === 'free') return json(c, { error: 'Invalid plan. Choose: pro, enterprise' }, 400);

  const tenant = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(t).first<any>();
  if (!tenant) return json(c, { error: 'Tenant not found' }, 404);
  if (tenant.plan === plan) return json(c, { error: 'Already on this plan' }, 400);

  const successUrl = sanitize(b.success_url || 'https://echo-op.com/dashboard?upgraded=true', 500);
  const cancelUrl = sanitize(b.cancel_url || 'https://echo-op.com/dashboard?cancelled=true', 500);
  const planInfo = PLAN_LIMITS[plan];

  // Create Stripe Checkout Session via URLSearchParams
  const params: Record<string, string> = {
    'mode': 'subscription',
    'success_url': successUrl,
    'cancel_url': cancelUrl,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][product_data][name]': `Echo Email Marketing - ${planInfo.name}`,
    'line_items[0][price_data][product_data][description]': `${planInfo.contacts === 999999999 ? 'Unlimited' : planInfo.contacts.toLocaleString()} contacts, ${planInfo.emails_month === 999999999 ? 'unlimited' : planInfo.emails_month.toLocaleString()} emails/mo`,
    'line_items[0][price_data][unit_amount]': planInfo.price_cents.toString(),
    'line_items[0][price_data][recurring][interval]': 'month',
    'line_items[0][quantity]': '1',
    'metadata[tenant_id]': t,
    'metadata[plan]': plan,
  };

  // Attach existing customer if we have one
  if (tenant.stripe_customer_id) {
    params['customer'] = tenant.stripe_customer_id;
  } else if (tenant.email) {
    params['customer_email'] = tenant.email;
  }

  try {
    const session = await stripeAPI(c.env, '/checkout/sessions', 'POST', params);
    if (session.error) {
      slog('error', 'Stripe checkout session creation failed', { error: session.error.message });
      return json(c, { error: session.error.message }, 400);
    }
    slog('info', 'Stripe checkout session created', { tenant_id: t, plan, session_id: session.id });
    return json(c, { checkout_url: session.url, session_id: session.id }, 201);
  } catch (e: any) {
    slog('error', 'Stripe API call failed', { error: e.message });
    return json(c, { error: 'Failed to create checkout session' }, 500);
  }
});

// === ADMIN: Stripe schema migration ===
app.post('/admin/migrate-stripe', async (c) => {
  const statements = [
    "ALTER TABLE tenants ADD COLUMN stripe_customer_id TEXT",
    "ALTER TABLE tenants ADD COLUMN plan_tier TEXT DEFAULT 'free'",
    "ALTER TABLE tenants ADD COLUMN plan_expires_at TEXT",
    "ALTER TABLE tenants ADD COLUMN updated_at TEXT DEFAULT (datetime('now'))",
  ];
  const results: { sql: string; status: string; error?: string }[] = [];
  for (const sql of statements) {
    try {
      await c.env.DB.prepare(sql).run();
      results.push({ sql, status: 'ok' });
    } catch (e: any) {
      // "duplicate column" is expected on re-run
      results.push({ sql, status: e.message?.includes('duplicate') ? 'already_exists' : 'error', error: e.message });
    }
  }
  slog('info', 'Stripe schema migration executed', { results });
  return json(c, { migrated: true, results });
});

// === AI ENDPOINTS ===
app.post('/ai/generate-subject', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  try {
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'MKT-01', query: `Generate 5 compelling email subject lines for: "${b.topic}". Tone: ${b.tone || 'professional'}. Industry: ${b.industry || 'general'}. Include emoji variants. Return as JSON array of strings.` }),
    });
    const data = await resp.json() as any;
    return json(c, { subjects: data.response || data });
  } catch { return json(c, { error: 'AI service unavailable' }, 503); }
});
app.post('/ai/generate-content', async (c) => {
  const b = sanitizeBody(await c.req.json()) as any;
  try {
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'MKT-01', query: `Write an email body for: "${b.topic}". Type: ${b.type || 'newsletter'}. Tone: ${b.tone || 'professional'}. Include a clear CTA. Return HTML-formatted email content.` }),
    });
    const data = await resp.json() as any;
    return json(c, { content: data.response || data });
  } catch { return json(c, { error: 'AI service unavailable' }, 503); }
});

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  slog('error', 'Unhandled request error', { error: err.message, stack: err.stack });
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// Scheduled: process automation steps + cleanup
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    // Process scheduled campaigns
    const scheduled = await env.DB.prepare("SELECT id FROM campaigns WHERE status='scheduled' AND scheduled_at <= datetime('now')").all();
    for (const camp of (scheduled.results || [])) {
      await env.DB.prepare("UPDATE campaigns SET status='sending' WHERE id=?").bind(camp.id).run();
    }
    // Clean old events (>1 year)
    await env.DB.prepare("DELETE FROM campaign_events WHERE created_at < datetime('now','-365 days')").run();
    await env.DB.prepare("DELETE FROM activity_log WHERE created_at < datetime('now','-90 days')").run();
  },
};
