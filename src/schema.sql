-- Echo Email Marketing v1.0.0 Schema
-- AI-powered email campaigns, automation, and analytics

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  plan TEXT DEFAULT 'free',
  max_contacts INTEGER DEFAULT 500,
  max_campaigns_month INTEGER DEFAULT 10,
  sender_name TEXT,
  sender_email TEXT,
  reply_to TEXT,
  branding_json TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  phone TEXT,
  company TEXT,
  tags TEXT DEFAULT '[]',
  custom_fields TEXT DEFAULT '{}',
  status TEXT DEFAULT 'active',
  subscribed_at TEXT DEFAULT (datetime('now')),
  unsubscribed_at TEXT,
  bounce_count INTEGER DEFAULT 0,
  last_email_at TEXT,
  last_opened_at TEXT,
  last_clicked_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_contact_tenant ON contacts(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_contact_email ON contacts(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_contact_status ON contacts(tenant_id, status);

CREATE TABLE IF NOT EXISTS lists (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  contact_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_list_tenant ON lists(tenant_id);

CREATE TABLE IF NOT EXISTS list_members (
  id TEXT PRIMARY KEY,
  list_id TEXT NOT NULL,
  contact_id TEXT NOT NULL,
  added_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (list_id) REFERENCES lists(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_listmember_unique ON list_members(list_id, contact_id);
CREATE INDEX IF NOT EXISTS idx_listmember_contact ON list_members(contact_id);

CREATE TABLE IF NOT EXISTS templates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  subject TEXT,
  html_content TEXT,
  text_content TEXT,
  category TEXT DEFAULT 'general',
  variables TEXT DEFAULT '[]',
  is_global INTEGER DEFAULT 0,
  use_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_template_tenant ON templates(tenant_id);

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  preview_text TEXT,
  from_name TEXT,
  from_email TEXT,
  reply_to TEXT,
  html_content TEXT,
  text_content TEXT,
  template_id TEXT,
  list_id TEXT,
  segment_filter TEXT DEFAULT '{}',
  status TEXT DEFAULT 'draft',
  type TEXT DEFAULT 'regular',
  ab_variant TEXT,
  ab_parent_id TEXT,
  scheduled_at TEXT,
  sent_at TEXT,
  total_sent INTEGER DEFAULT 0,
  total_delivered INTEGER DEFAULT 0,
  total_opened INTEGER DEFAULT 0,
  total_clicked INTEGER DEFAULT 0,
  total_bounced INTEGER DEFAULT 0,
  total_unsubscribed INTEGER DEFAULT 0,
  total_complained INTEGER DEFAULT 0,
  open_rate REAL DEFAULT 0,
  click_rate REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_tenant ON campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaign_status ON campaigns(tenant_id, status);

CREATE TABLE IF NOT EXISTS campaign_events (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  contact_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',
  ip_address TEXT,
  user_agent TEXT,
  link_url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
CREATE INDEX IF NOT EXISTS idx_event_campaign ON campaign_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_event_contact ON campaign_events(contact_id);
CREATE INDEX IF NOT EXISTS idx_event_type ON campaign_events(campaign_id, event_type);

CREATE TABLE IF NOT EXISTS automations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  trigger_type TEXT NOT NULL,
  trigger_config TEXT DEFAULT '{}',
  steps_json TEXT DEFAULT '[]',
  status TEXT DEFAULT 'inactive',
  enrolled_count INTEGER DEFAULT 0,
  completed_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_auto_tenant ON automations(tenant_id);

CREATE TABLE IF NOT EXISTS automation_enrollments (
  id TEXT PRIMARY KEY,
  automation_id TEXT NOT NULL,
  contact_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  current_step INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  next_action_at TEXT,
  enrolled_at TEXT DEFAULT (datetime('now')),
  completed_at TEXT,
  FOREIGN KEY (automation_id) REFERENCES automations(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);
CREATE INDEX IF NOT EXISTS idx_autoenroll_auto ON automation_enrollments(automation_id);
CREATE INDEX IF NOT EXISTS idx_autoenroll_next ON automation_enrollments(status, next_action_at);

CREATE TABLE IF NOT EXISTS unsubscribes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  contact_id TEXT NOT NULL,
  campaign_id TEXT,
  reason TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_unsub_tenant ON unsubscribes(tenant_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_id TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id);
