// 炽云AI 内部工作台 · Pages Functions API
// 路由前缀 /api/*，数据存储 Cloudflare D1（binding: DB）
import { SEED } from '../seed.js';

const COOKIE_NAME = 'cy_sid';
const SESSION_DAYS = 30;
const MAX_IMG = 900 * 1024;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
const fail = (msg, status = 400) => json({ ok: false, error: msg }, status);
const ok = (data = {}) => json({ ok: true, ...data });

const enc = new TextEncoder();
const toHex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
};
const randHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));

async function hashPassword(pw, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: 30000 },
    key,
    256
  );
  return toHex(new Uint8Array(bits));
}

function readCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  for (const part of c.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

function sessionCookie(token, maxAge = SESSION_DAYS * 86400) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

const clean = (v, max = 5000) => String(v == null ? '' : v).trim().slice(0, max);
const boolInt = (v) => (v ? 1 : 0);

async function currentUser(env, req) {
  const token = readCookie(req, COOKIE_NAME);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.name, u.role, u.title, u.phone, u.wechat, u.created_at,
            u.role_type, u.parent_id, u.channel_code, u.commission_rate, u.team_no, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > datetime('now') AND u.status = 'active'`
  )
    .bind(token)
    .first();
  return row || null;
}

function isAdmin(u) {
  return u && u.role === 'admin';
}
function canEdit(u, ownerId) {
  return isAdmin(u) || Number(u.id) === Number(ownerId);
}

async function createSession(env, userId) {
  const token = randHex(24);
  await env.DB.prepare(
    `INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
  )
    .bind(token, userId)
    .run();
  await env.DB.prepare(`UPDATE users SET last_login = datetime('now') WHERE id = ?`).bind(userId).run();
  return token;
}

async function masterLogin(env, role) {
  const username = role === 'admin' ? 'zx123' : 'staff';
  let user = await env.DB.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first();
  if (!user) {
    const salt = randHex(16);
    const pass = await hashPassword(randHex(16), salt);
    const res = await env.DB.prepare(
      `INSERT INTO users (username, name, role, pass_hash, pass_salt, title)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(username, role === 'admin' ? '管理账号' : '公共体验账号', role, pass, salt, role === 'admin' ? '老板 / 管理层' : '公共账号')
      .run();
    user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(res.meta.last_row_id).first();
  }
  const token = await createSession(env, user.id);
  return { user, token };
}

const PWD_CHARS = 'abcdefghjkmnpqrstuvwxyz23456789';
function genPassword(len = 8) {
  const a = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(a).map((n) => PWD_CHARS[n % PWD_CHARS.length]).join('');
}

async function genUsername(env) {
  const { results } = await env.DB.prepare(`SELECT username FROM users`).all();
  let max = 0;
  for (const r of results) {
    const m = /^cy(\d+)$/.exec(r.username);
    if (m) max = Math.max(max, Number(m[1]));
  }
  let n = max + 1;
  for (;;) {
    const candidate = 'cy' + String(n).padStart(3, '0');
    const dup = await env.DB.prepare(`SELECT id FROM users WHERE username = ?`).bind(candidate).first();
    if (!dup) return candidate;
    n++;
  }
}

// 团队编号：合伙人 001/002…，成员 001-01/001-02…（前缀即团号，隔级裂变仍能识别归属）
async function genTeamNo(env, parentId) {
  const pid = Number(parentId || 0);
  if (!pid) {
    const { results } = await env.DB.prepare(
      `SELECT team_no FROM users WHERE team_no GLOB '[0-9][0-9][0-9]'`
    ).all();
    let max = 0;
    for (const r of results) max = Math.max(max, Number(r.team_no) || 0);
    return String(max + 1).padStart(3, '0');
  }
  const p = await env.DB.prepare(`SELECT team_no FROM users WHERE id = ?`).bind(pid).first();
  let root = (p && /^\d{3}/.test(p.team_no || '')) ? p.team_no.slice(0, 3) : '';
  if (!root) {
    root = await genTeamNo(env, 0);
    await env.DB.prepare(`UPDATE users SET team_no = ? WHERE id = ? AND (team_no IS NULL OR team_no = '')`).bind(root, pid).run();
  }
  const { results: sibs } = await env.DB.prepare(
    `SELECT team_no FROM users WHERE team_no LIKE ?`
  ).bind(root + '-%').all();
  let max = 0;
  for (const r of sibs) {
    const m = /-(\d+)$/.exec(r.team_no || '');
    if (m) max = Math.max(max, Number(m[1]) || 0);
  }
  return root + '-' + String(max + 1).padStart(2, '0');
}

// 老库回填：按 id 升序给无编号的推广员/合伙人补号（幂等，只处理空号）
async function backfillTeamNos(env) {
  const { results } = await env.DB.prepare(
    `SELECT id, parent_id, role_type, role FROM users
       WHERE (team_no IS NULL OR team_no = '') AND status = 'active' ORDER BY id ASC`
  ).all();
  for (const u of results) {
    if (u.role === 'admin') continue;
    if (!['agent', 'leader'].includes(u.role_type || '')) continue;
    const no = await genTeamNo(env, u.parent_id);
    await env.DB.prepare(
      `UPDATE users SET team_no = ? WHERE id = ? AND (team_no IS NULL OR team_no = '')`
    ).bind(no, u.id).run();
  }
}

async function createMember(env, body) {
  const name = clean(body.name, 32);
  if (!name) return fail('请填写姓名');
  const username = await genUsername(env);
  const password = genPassword(8);
  const salt = randHex(16);
  const hash = await hashPassword(password, salt);
  await env.DB.prepare(
    `INSERT INTO users (username, name, role, pass_hash, pass_salt, title, phone, team_no)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(username, name, body.role === 'admin' ? 'admin' : 'staff', hash, salt, clean(body.title, 32), clean(body.phone, 32), '')
    .run();
  return ok({ username, password });
}

async function handleRegister(env, body) {
  const code = clean(body.code, 64).toUpperCase();
  const name = clean(body.name, 32);
  const password = String(body.password || '');
  if (!code) return fail('请填写邀请码');
  if (!name) return fail('请填写姓名');
  if (password.length < 6) return fail('密码至少 6 位');
  const phone = clean(body.phone, 32);
  // 防伪装：手机号必填且唯一。客户的手机号若已注册为推广员，报备环节会被拦截；推广员没手机号则无法溯源
  if (!phone) return fail('请填写本人手机号（佣金归属与防套佣都靠它）');
  if (!/^1\d{10}$/.test(phone)) return fail('手机号格式不对（11位数字）');
  const inv = await env.DB.prepare(`SELECT * FROM invites WHERE code = ? AND active = 1`).bind(code).first();
  if (!inv) return fail('邀请码无效或已停用');
  const phoneDup = await env.DB.prepare(`SELECT id FROM users WHERE phone = ? LIMIT 1`).bind(phone).first();
  if (phoneDup) return fail('该手机号已注册过，请直接登录或联系管理员');
  const username = await genUsername(env);
  const salt = randHex(16);
  const hash = await hashPassword(password, salt);
  // 子码裂变：用成员子码注册 → 自动挂到该成员名下（parent_id），渠道号=子码，角色=推广员
  const ownerId = Number(inv.owner_id) || 0;
  const teamNo = await genTeamNo(env, ownerId);
  const res = await env.DB.prepare(
    `INSERT INTO users (username, name, role, pass_hash, pass_salt, phone, role_type, parent_id, channel_code, commission_rate, team_no)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(username, name, inv.role === 'admin' ? 'admin' : 'staff', hash, salt, clean(body.phone, 32),
      ownerId ? 'agent' : null, ownerId, ownerId ? code : '', ownerId ? 0.03 : 0.4, teamNo)
    .run();
  await env.DB.prepare(`UPDATE invites SET used_count = used_count + 1 WHERE code = ?`).bind(code).run();
  // 裂变即时反馈：新势力用子码注册成功 → 立刻通知合伙人（正反馈越快，带人越起劲）
  if (ownerId) {
    await notify(env, ownerId, 'invite', '你的新势力上线了：' + name,
      name + ' 已用你的邀请码 ' + code + ' 加入团队。记得主动带TA跑通第一单——TA出首单（客户实付≥500）你有 30 元推荐奖。', '/console?tab=members');
  }
  const token = await createSession(env, res.meta.last_row_id);
  const user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(res.meta.last_row_id).first();
  return new Response(JSON.stringify({ ok: true, user: publicUser(user), username }), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'set-cookie': sessionCookie(token), 'cache-control': 'no-store' },
  });
}

async function handleLogin(env, body) {
  const username = clean(body.username, 32);
  const password = String(body.password || '');
  if (!password) return fail('请输入密码');

  if (password === 'zx123') {
    const { user, token } = await masterLogin(env, 'admin');
    return new Response(JSON.stringify({ ok: true, user: publicUser(user) }), {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8', 'set-cookie': sessionCookie(token), 'cache-control': 'no-store' },
    });
  }
  if (password === '147258') {
    const { user, token } = await masterLogin(env, 'staff');
    return new Response(JSON.stringify({ ok: true, user: publicUser(user) }), {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8', 'set-cookie': sessionCookie(token), 'cache-control': 'no-store' },
    });
  }
  if (!username) return fail('请输入账号');

  const user = await env.DB.prepare(`SELECT * FROM users WHERE username = ? AND status = 'active'`).bind(username).first();
  if (!user) return fail('账号或密码错误', 401);
  const hash = await hashPassword(password, user.pass_salt);
  if (hash !== user.pass_hash) return fail('账号或密码错误', 401);
  const token = await createSession(env, user.id);
  return new Response(JSON.stringify({ ok: true, user: publicUser(user) }), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'set-cookie': sessionCookie(token), 'cache-control': 'no-store' },
  });
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    name: u.name,
    role: u.role,
    title: u.title || '',
    phone: u.phone || '',
    wechat: u.wechat || '',
    created_at: u.created_at,
    role_type: u.role_type || 'staff',
    parent_id: Number(u.parent_id || 0),
    channel_code: u.channel_code || '',
    commission_rate: Number(u.commission_rate || 0),
    team_no: u.team_no || '',
  };
}

// ---------- 各模块 ----------

async function listLogs(env, user) {
  // 合伙人只能看到自己的日志，全员日志仅管理员可见
  const own = user.role !== 'admin' ? ` WHERE l.user_id = ${Number(user.id)}` : '';
  const { results } = await env.DB.prepare(
    `SELECT l.*, u.name AS user_name, u.role AS user_role
       FROM daily_logs l JOIN users u ON u.id = l.user_id${own}
      ORDER BY l.log_date DESC, l.id DESC LIMIT 200`
  ).all();
  return ok({ items: results });
}

async function listAccounts(env) {
  const { results } = await env.DB.prepare(
    `SELECT a.*, u.name AS owner_name FROM account_ledger a JOIN users u ON u.id = a.owner_id
      ORDER BY a.updated_at DESC LIMIT 300`
  ).all();
  return ok({ items: results });
}

async function listCustomers(env, user) {
  const { results } = await env.DB.prepare(
    `SELECT c.*, u.name AS owner_name, sa.name AS source_agent_name
       FROM customers c JOIN users u ON u.id = c.owner_id
       LEFT JOIN users sa ON sa.id = c.source_agent_id
      ORDER BY c.updated_at DESC LIMIT 300`
  ).all();
  const items = results.map((r) => {
    const mine = canEdit(user, r.owner_id) || Number(r.source_agent_id) === user.id;
    return {
      id: r.id,
      owner_id: r.owner_id,
      owner_name: r.owner_name,
      name: r.name,
      company: r.company,
      industry: r.industry,
      stage: r.stage,
      amount: r.amount,
      created_at: r.created_at,
      updated_at: r.updated_at,
      mine,
      source_agent_id: Number(r.source_agent_id || 0),
      source_agent_name: r.source_agent_name || '',
      report_date: r.report_date || '',
      channel_code: r.channel_code || '',
      biz_line: r.biz_line || '算力',
      protected_until: r.protected_until || '',
      contact: mine ? r.contact : mask(r.contact),
      phone: mine ? r.phone : mask(r.phone),
      wechat: mine ? r.wechat : mask(r.wechat),
      note: mine ? r.note : '',
    };
  });
  return ok({ items });
}

const mask = (s) => (s ? String(s).replace(/.(?=.{0,1}$)/g, '*') : '');

async function statsFor(env, user) {
  const today = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
  const q = (sql, ...args) => env.DB.prepare(sql).bind(...args).first();
  // 合伙人（非管理员）：只回自己的基础数据，不透露公司内部台账
  if (user.role !== 'admin') {
    const month = today.slice(0, 7);
    const [myCus, myComm, myInv, todos] = await Promise.all([
      q(`SELECT COUNT(*) AS n FROM customers WHERE source_agent_id = ?`, user.id),
      q(`SELECT COALESCE(SUM(amount),0) AS n FROM commissions WHERE agent_id = ? AND month = ?`, user.id, month),
      q(`SELECT COUNT(*) AS n FROM invites WHERE owner_id = ? AND active = 1`, user.id),
      q(`SELECT COUNT(*) AS n FROM todos WHERE done = 0 AND user_id = ?`, user.id),
    ]);
    return ok({
      stats: {
        members: 0, logsToday: 0, accounts: 0,
        customers: myCus.n, todos: todos.n, today,
        my_commission: myComm.n, my_invites: myInv.n, scope: 'self',
      },
    });
  }
  const [members, logsToday, accounts, customers, todos] = await Promise.all([
    q(`SELECT COUNT(*) AS n FROM users WHERE status = 'active'`),
    q(`SELECT COUNT(*) AS n FROM daily_logs WHERE log_date = ?`, today),
    q(`SELECT COUNT(*) AS n FROM account_ledger`),
    q(`SELECT COUNT(*) AS n FROM customers`),
    q(`SELECT COUNT(*) AS n FROM todos WHERE done = 0 AND user_id = ?`, user.id),
  ]);
  return ok({
    stats: {
      members: members.n,
      logsToday: logsToday.n,
      accounts: accounts.n,
      customers: customers.n,
      todos: todos.n,
      today,
    },
  });
}

// ---------- 站内通知 / webhook / 种子导入 ----------

async function getSetting(env, key) {
  const r = await env.DB.prepare(`SELECT value FROM settings WHERE key = ?`).bind(key).first();
  return r ? r.value : '';
}
async function setSetting(env, key, value) {
  await env.DB.prepare(
    `INSERT INTO settings(key, value, updated_at) VALUES(?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).bind(key, String(value || '')).run();
}

// 站内通知：写库 + 有 webhook 时异步推送（失败静默，不影响主流程）
async function notify(env, userId, kind, title, content, link) {
  try {
    await env.DB.prepare(
      `INSERT INTO notifications(user_id, kind, title, content, link) VALUES(?, ?, ?, ?, ?)`
    ).bind(userId, kind, clean(title, 120), clean(content, 500), clean(link, 300)).run();
  } catch (e) { /* 通知失败不影响业务 */ }
  const hook = await getSetting(env, 'webhook_url');
  if (hook && /^https:\/\//.test(hook)) {
    const text = `【炽云AI工作台】${title}\n${content || ''}${link ? '\n' + link : ''}`;
    // 不 await：避免外部 webhook 拖慢响应
    fetch(hook, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ msgtype: 'text', text: { content: text } }),
    }).catch(() => {});
  }
}

async function notifyAdmins(env, exceptId, kind, title, content, link) {
  const { results } = await env.DB.prepare(`SELECT id FROM users WHERE role = 'admin' AND status = 'active'`).all();
  await Promise.all(results.filter(u => u.id !== exceptId).map(u => notify(env, u.id, kind, title, content, link)));
}

async function firstAdminId(env) {
  const r = await env.DB.prepare(`SELECT id FROM users WHERE role = 'admin' AND status = 'active' ORDER BY id ASC LIMIT 1`).first();
  return r ? r.id : 1;
}

// 自动建表：部署后无需手工执行 SQL，首次调用即补齐所有表（幂等，兼容空库与已有库）
async function ensureTables(env) {
  const ddl = [
    `CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
       role TEXT NOT NULL DEFAULT 'staff', pass_hash TEXT NOT NULL, pass_salt TEXT NOT NULL,
       title TEXT DEFAULT '', phone TEXT DEFAULT '', wechat TEXT DEFAULT '',
       status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT (datetime('now')), last_login TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS sessions (
       token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL,
       created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
    `CREATE TABLE IF NOT EXISTS invites (
       code TEXT PRIMARY KEY, role TEXT NOT NULL DEFAULT 'staff', note TEXT DEFAULT '',
       active INTEGER NOT NULL DEFAULT 1, used_count INTEGER NOT NULL DEFAULT 0,
       created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS account_ledger (
       id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, platform TEXT NOT NULL,
       account_name TEXT NOT NULL, url TEXT DEFAULT '', category TEXT DEFAULT '社媒',
       status TEXT DEFAULT '运营中', fans TEXT DEFAULT '', note TEXT DEFAULT '',
       created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_accounts_owner ON account_ledger(owner_id)`,
    `CREATE TABLE IF NOT EXISTS daily_logs (
       id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, log_date TEXT NOT NULL,
       done TEXT DEFAULT '', plan TEXT DEFAULT '', issue TEXT DEFAULT '', content TEXT NOT NULL,
       created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_logs_date ON daily_logs(log_date)`,
    `CREATE TABLE IF NOT EXISTS customers (
       id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL,
       company TEXT DEFAULT '', contact TEXT DEFAULT '', phone TEXT DEFAULT '', wechat TEXT DEFAULT '',
       industry TEXT DEFAULT '', stage TEXT DEFAULT '线索', amount TEXT DEFAULT '', note TEXT DEFAULT '',
       created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_customers_owner ON customers(owner_id)`,
    `CREATE TABLE IF NOT EXISTS customer_notes (
       id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
       content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_cnotes_customer ON customer_notes(customer_id)`,
    `CREATE TABLE IF NOT EXISTS todos (
       id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
       detail TEXT DEFAULT '', due_date TEXT DEFAULT '', priority TEXT DEFAULT '普通',
       done INTEGER NOT NULL DEFAULT 0, done_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_todos_user ON todos(user_id)`,
    `CREATE TABLE IF NOT EXISTS comments (
       id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT NOT NULL, target_id INTEGER NOT NULL,
       user_id INTEGER NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_comments_target ON comments(target_type, target_id)`,
    `CREATE TABLE IF NOT EXISTS announcements (
       id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
       content TEXT NOT NULL, pinned INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS files (
       id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
       kind TEXT DEFAULT 'link', url TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS file_blobs (file_id INTEGER PRIMARY KEY, mime TEXT NOT NULL, data BLOB NOT NULL)`,
    // v2 新增
    `CREATE TABLE IF NOT EXISTS messages (
       id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER NOT NULL, to_id INTEGER NOT NULL,
       content TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_id, to_id, id)`,
    `CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_id, read_at)`,
    `CREATE TABLE IF NOT EXISTS approvals (
       id INTEGER PRIMARY KEY AUTOINCREMENT, applicant_id INTEGER NOT NULL, approver_id INTEGER NOT NULL,
       kind TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL, amount TEXT DEFAULT '',
       status TEXT NOT NULL DEFAULT '待审批', handled_at TEXT, handle_note TEXT DEFAULT '',
       created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_appr_status ON approvals(status, id)`,
    `CREATE INDEX IF NOT EXISTS idx_appr_approver ON approvals(approver_id, status)`,
    `CREATE TABLE IF NOT EXISTS notifications (
       id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
       title TEXT NOT NULL, content TEXT DEFAULT '', link TEXT DEFAULT '',
       read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_notice_user ON notifications(user_id, read, id)`,
    `CREATE TABLE IF NOT EXISTS docs (
       id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT DEFAULT '综合',
       summary TEXT DEFAULT '', content TEXT NOT NULL DEFAULT '', source TEXT DEFAULT '', tags TEXT DEFAULT '',
       created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_docs_cat ON docs(category, id)`,
    `CREATE TABLE IF NOT EXISTS settings (
       key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `INSERT OR IGNORE INTO settings(key, value) VALUES ('seed_v2', '0')`,
    `INSERT OR IGNORE INTO settings(key, value) VALUES ('webhook_url', '')`,
    `INSERT OR IGNORE INTO settings(key, value) VALUES ('workspace_name', '炽云AI · 内部工作台')`,
    `INSERT OR IGNORE INTO settings(key, value) VALUES ('platforms', '')`,

    // ===== 推广体系 v3 =====
    // 已有表加列（重复执行会报 duplicate column，忽略即可）
    `ALTER TABLE users ADD COLUMN role_type TEXT DEFAULT 'staff'`,
    `ALTER TABLE users ADD COLUMN parent_id INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN channel_code TEXT DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN commission_rate REAL DEFAULT 0.4`,
    `ALTER TABLE users ADD COLUMN team_no TEXT DEFAULT ''`,
    `ALTER TABLE customers ADD COLUMN source_agent_id INTEGER DEFAULT 0`,
    `ALTER TABLE customers ADD COLUMN report_date TEXT DEFAULT ''`,
    `ALTER TABLE customers ADD COLUMN channel_code TEXT DEFAULT ''`,
    `ALTER TABLE customers ADD COLUMN biz_line TEXT DEFAULT '算力'`,
    `ALTER TABLE customers ADD COLUMN protected_until TEXT DEFAULT ''`,
    // 佣金规则：按业务线+档位配置
    `CREATE TABLE IF NOT EXISTS commission_rules (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       biz_line TEXT NOT NULL, tier TEXT NOT NULL, rate REAL NOT NULL,
       note TEXT DEFAULT '', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    // 佣金结算记录
    `CREATE TABLE IF NOT EXISTS commissions (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       agent_id INTEGER NOT NULL, month TEXT NOT NULL, biz_line TEXT DEFAULT '算力',
       gross REAL NOT NULL DEFAULT 0, rate REAL NOT NULL DEFAULT 0,
       amount REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT '待结算',
       note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE INDEX IF NOT EXISTS idx_comm_agent ON commissions(agent_id, month)`,
    // 默认佣金规则（INSERT OR IGNORE 靠唯一约束：用 code 组合键避免重复）
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_unique ON commission_rules(biz_line, tier)`,
    // v6 规则：按"客户实付流水"计佣。算力毛利 = 甲方推广提成 0.1584元/卡时 ÷ 客户实付1.94 ≈ 8.16%，
    // 首月3%/续费1.5% = 毛利的约三成七/一成八——公司留大头，绝不对半分
    `INSERT OR IGNORE INTO commission_rules(biz_line, tier, rate, note) VALUES
       ('算力','常规',0.03,'首月：客户实付的3%（月花2000拿60）'),
       ('算力','续费',0.015,'续费月：客户实付的1.5%（月花2000拿30）'),
       ('海外模型','常规',0.03,'首月：客户实付的3%'),
       ('海外模型','续费',0.02,'续费月：客户实付的2%'),
       ('裸金属','常规',0.03,'首月：客户实付的3%（月花2000拿60）'),
       ('裸金属','续费',0.015,'续费月：客户实付的1.5%（月花2000拿30）'),
       ('训力券','常规',0.03,'首月：客户实付的3%'),
       ('训力券','续费',0.02,'续费月：客户实付的2%'),
       ('建站服务','常规',0.10,'一次性合同额的10%'),
       ('建站服务','续费',0.05,'维护续费的5%'),
       ('OPC招商','常规',0.08,'首月租金的8%'),
       ('OPC招商','续费',0.06,'续租租金的6%'),
       ('公寓出租','常规',0.20,'首月租金的20%'),
       ('公寓出租','续费',0.10,'续租租金的10%'),
       ('服务器售卖','常规',0.02,'一次性合同额的2%（整机大额单：10万的机器拿2000）'),
       ('服务器售卖','续费',0.02,'复购另一台同样2%（老客复购按常规档）')`,
    `ALTER TABLE invites ADD COLUMN owner_id INTEGER DEFAULT 0`,
    // ===== 资料密级 =====
    // docs 默认仅管理员；files 默认对合伙人公开（管理员可单条收归内部）
    `ALTER TABLE docs ADD COLUMN visibility TEXT DEFAULT 'internal'`,
    `ALTER TABLE files ADD COLUMN visibility TEXT DEFAULT 'public'`,
  ];
  for (const sql of ddl) {
    try { await env.DB.prepare(sql).run(); } catch (e) { /* 表/索引已存在则忽略 */ }
  }
  // 一次性迁移：老库还是"按毛利分成"的旧费率（算力|新人首月=0.5）→ 重写为 v5 流水制
  try {
    const old = await env.DB.prepare(`SELECT rate FROM commission_rules WHERE biz_line='算力' AND tier='新人首月'`).first();
    if (old && Number(old.rate) === 0.5) {
      const stmts = [
        `DELETE FROM commission_rules WHERE tier IN ('新人首月','超额','旗舰','走量')`,
        `UPDATE commission_rules SET rate=0.03, note='首月：客户实付的3%（月花2000拿60）' WHERE biz_line IN ('算力','裸金属') AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.015, note='续费月：客户实付的1.5%（月花2000拿30）' WHERE biz_line IN ('算力','裸金属') AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.03, note='首月：客户实付的3%' WHERE biz_line='海外模型' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.02, note='续费月：客户实付的2%' WHERE biz_line='海外模型' AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.03, note='首月：客户实付的3%' WHERE biz_line='训力券' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.02, note='续费月：客户实付的2%' WHERE biz_line='训力券' AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.10, note='一次性合同额的10%' WHERE biz_line='建站服务' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.08, note='首月租金的8%' WHERE biz_line='OPC招商' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.06, note='续租租金的6%' WHERE biz_line='OPC招商' AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.20, note='首月租金的20%' WHERE biz_line='公寓出租' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.10, note='续租租金的10%' WHERE biz_line='公寓出租' AND tier='续费'`,
      ];
      for (const s of stmts) { try { await env.DB.prepare(s).run(); } catch (e) {} }
    }
    // v4→v5 迁移：上一版 5%/3% 档 → 直接写 v6 终值
    const v4 = await env.DB.prepare(`SELECT rate FROM commission_rules WHERE biz_line='算力' AND tier='常规'`).first();
    if (v4 && Number(v4.rate) === 0.05) {
      const stmts2 = [
        `UPDATE commission_rules SET rate=0.03, note='首月：客户实付的3%（月花2000拿60）' WHERE biz_line IN ('算力','裸金属') AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.015, note='续费月：客户实付的1.5%（月花2000拿30）' WHERE biz_line IN ('算力','裸金属') AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.03, note='首月：客户实付的3%' WHERE biz_line IN ('海外模型','训力券') AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.02, note='续费月：客户实付的2%' WHERE biz_line IN ('海外模型','训力券') AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.10, note='一次性合同额的10%' WHERE biz_line='建站服务' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.08, note='首月租金的8%' WHERE biz_line='OPC招商' AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.06, note='续租租金的6%' WHERE biz_line='OPC招商' AND tier='续费'`,
        `UPDATE commission_rules SET rate=0.20, note='首月租金的20%' WHERE biz_line='公寓出租' AND tier='常规'`,
      ];
      for (const s of stmts2) { try { await env.DB.prepare(s).run(); } catch (e) {} }
    }
    // v5→v6 迁移：4%/2% 档（把毛利对半分出去了）→ 修正为 3%/1.5%（毛利的约三成七/一成八，公司留大头）
    const v5 = await env.DB.prepare(`SELECT rate FROM commission_rules WHERE biz_line='算力' AND tier='常规'`).first();
    if (v5 && Number(v5.rate) === 0.04) {
      const stmts3 = [
        `UPDATE commission_rules SET rate=0.03, note='首月：客户实付的3%（月花2000拿60）' WHERE biz_line IN ('算力','裸金属') AND tier='常规'`,
        `UPDATE commission_rules SET rate=0.015, note='续费月：客户实付的1.5%（月花2000拿30）' WHERE biz_line IN ('算力','裸金属') AND tier='续费'`,
      ];
      for (const s of stmts3) { try { await env.DB.prepare(s).run(); } catch (e) {} }
    }
  } catch (e) {}
  // 资料密级初始化（只跑一次）：
  // 甲方与公司签的协议、结算价、上游成本、内部台账一律 internal，合伙人不可见；
  // 公司/产品/报价/答疑等对外资料进白名单 public——合伙人也要了解公司。
  try {
    const visDone = await getSetting(env, 'doc_vis_v1');
    if (visDone !== '1') {
      await env.DB.prepare(`UPDATE docs SET visibility='internal'`).run();
      const PUBLIC_DOCS = [
        '项目简介', '算力报价单', '公司介绍', '产品线与计费', '价格表',
        'GPU选型与服务器配置', '场地与入驻', '高频问答', '上机与技术排错',
        '客户补充问答', '海外模型与合规边界'
      ];
      for (const t of PUBLIC_DOCS) {
        await env.DB.prepare(`UPDATE docs SET visibility='public' WHERE title = ?`).bind(t).run();
      }
      await env.DB.prepare(`UPDATE files SET visibility='public'`).run();
      await env.DB.prepare(
        `UPDATE files SET visibility='internal' WHERE title LIKE '%合同%' OR title LIKE '%协议%'
          OR title LIKE '%结算%' OR title LIKE '%对公%' OR title LIKE '%成本%'
          OR title LIKE '%毛利%' OR title LIKE '%提成%' OR note LIKE '%甲方%' OR note LIKE '%0.1584%'`
      ).run();
      await setSetting(env, 'doc_vis_v1', '1');
    }
  } catch (e) {}
  // 团队编号回填（每次登录/注册幂等执行，老库自动补齐）
  try { await backfillTeamNos(env); } catch (e) {}
}

async function importSeed(env) {
  await ensureTables(env);
  if (!SEED) return { error: '种子数据未加载' };
  let v = await getSetting(env, 'seed_v2');
  if (v === '1') return { skipped: true };
  const adminId = await firstAdminId(env);
  const now = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);

  // 工作日志
  for (const l of SEED.logs || []) {
    const exists = await env.DB.prepare(`SELECT id FROM daily_logs WHERE user_id = ? AND log_date = ?`).bind(adminId, l.date).first();
    if (exists) continue;
    await env.DB.prepare(
      `INSERT INTO daily_logs(user_id, log_date, done, content, plan, issue) VALUES(?, ?, ?, ?, ?, ?)`
    ).bind(adminId, l.date, clean(l.done, 4000), clean(l.content, 8000), clean(l.plan, 4000), clean(l.issue, 2000)).run();
  }
  // 知识资料
  for (const d of SEED.docs || []) {
    const exists = await env.DB.prepare(`SELECT id FROM docs WHERE title = ? AND source = ?`).bind(d.title, d.source || '').first();
    if (exists) continue;
    await env.DB.prepare(
      `INSERT INTO docs(title, category, summary, content, source, tags) VALUES(?, ?, ?, ?, ?, ?)`
    ).bind(clean(d.title, 120), clean(d.category, 32), clean(d.summary, 500), clean(d.content, 8000), clean(d.source, 300), clean(d.tags || '', 200)).run();
  }
  // 运营账号
  for (const a of SEED.accounts || []) {
    const exists = await env.DB.prepare(`SELECT id FROM account_ledger WHERE platform = ? AND account_name = ?`).bind(a.platform, a.account_name).first();
    if (exists) continue;
    await env.DB.prepare(
      `INSERT INTO account_ledger(owner_id, platform, account_name, category, status, note) VALUES(?, ?, ?, ?, ?, ?)`
    ).bind(adminId, clean(a.platform, 32), clean(a.account_name, 64), clean(a.category || '社媒', 16), clean(a.status || '运营中', 16), clean(a.note, 1000)).run();
  }
  // 公告
  for (const a of SEED.announcements || []) {
    const exists = await env.DB.prepare(`SELECT id FROM announcements WHERE title = ?`).bind(a.title).first();
    if (exists) continue;
    await env.DB.prepare(`INSERT INTO announcements(user_id, title, content, pinned) VALUES(?, ?, ?, ?)`)
      .bind(adminId, clean(a.title, 120), clean(a.content, 5000), a.pinned ? 1 : 0).run();
  }
  // 待办
  for (const t of SEED.todos || []) {
    const exists = await env.DB.prepare(`SELECT id FROM todos WHERE user_id = ? AND title = ?`).bind(adminId, t.title).first();
    if (exists) continue;
    await env.DB.prepare(`INSERT INTO todos(user_id, title, detail, priority) VALUES(?, ?, ?, ?)`)
      .bind(adminId, clean(t.title, 120), clean(t.detail, 2000), clean(t.priority || '普通', 8)).run();
  }
  await setSetting(env, 'seed_v2', '1');
  return { skipped: false, logs: SEED.logs.length, docs: SEED.docs.length, accounts: SEED.accounts.length };
}

// ---------- 入口 ----------

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const seg = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  const method = request.method;
  const path = seg.join('/');

  if (!env.DB) return fail('数据库未绑定，请在 Pages 项目里配置 D1 binding: DB', 500);

  try {
    // 无需登录
    if (path === 'login' && method === 'POST') { await ensureTables(env); return await handleLogin(env, await request.json().catch(() => ({}))); }
    if (path === 'register' && method === 'POST') { await ensureTables(env); return await handleRegister(env, await request.json().catch(() => ({}))); }
    if (path === 'ping') return ok({ pong: true, time: new Date().toISOString() });

    const user = await currentUser(env, request);
    if (!user) return fail('未登录', 401);

    // 会话
    if (path === 'me' && method === 'GET') return ok({ user: publicUser(user) });
    if (path === 'logout' && method === 'POST') {
      const token = readCookie(request, COOKIE_NAME);
      if (token) await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json', 'set-cookie': sessionCookie('', 0) },
      });
    }
    if (path === 'stats' && method === 'GET') return await statsFor(env, user);
    if (path === 'overview' && method === 'GET') {
      const [ann, logs, todos] = await Promise.all([
        env.DB.prepare(`SELECT a.*, u.name AS user_name FROM announcements a JOIN users u ON u.id = a.user_id ORDER BY a.pinned DESC, a.id DESC LIMIT 5`).all(),
        env.DB.prepare(`SELECT l.*, u.name AS user_name FROM daily_logs l JOIN users u ON u.id = l.user_id ORDER BY l.id DESC LIMIT 5`).all(),
        env.DB.prepare(`SELECT * FROM todos WHERE user_id = ? AND done = 0 ORDER BY due_date ASC, id DESC LIMIT 6`).bind(user.id).all(),
      ]);
      return ok({ announcements: ann.results, logs: isAdmin(user) ? logs.results : [], todos: todos.results });
    }

    // 成员（名单含手机/微信，仅管理员）
    if (path === 'members' && method === 'GET' && !isAdmin(user)) return fail('仅管理员可查看团队成员', 403);
    if (path === 'members' && method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT u.id, u.username, u.name, u.role, u.title, u.phone, u.wechat, u.created_at, u.last_login, u.team_no,
                (SELECT COUNT(*) FROM account_ledger a WHERE a.owner_id = u.id) AS account_count,
                (SELECT COUNT(*) FROM customers c WHERE c.owner_id = u.id) AS customer_count,
                (SELECT COUNT(*) FROM daily_logs l WHERE l.user_id = u.id) AS log_count
           FROM users u WHERE u.status = 'active' ORDER BY u.role DESC, u.id ASC`
      ).all();
      return ok({ items: results });
    }
    if (path === 'members' && method === 'POST' && isAdmin(user)) {
      return await createMember(env, await request.json());
    }
    if (seg[0] === 'members' && seg[2] === 'reset' && method === 'POST' && isAdmin(user)) {
      const id = Number(seg[1]);
      const target = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(id).first();
      if (!target) return fail('成员不存在', 404);
      const password = genPassword(8);
      const salt = randHex(16);
      const hash = await hashPassword(password, salt);
      await env.DB.prepare(`UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?`).bind(hash, salt, id).run();
      await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(id).run();
      return ok({ username: target.username, password });
    }

    // 邀请码：管理员发总码；推广成员可生成自己前缀的子码（如 CY001-K3），邀来的人自动归属其名下
    if (path === 'invites' && method === 'GET') {
      if (isAdmin(user)) {
        const { results } = await env.DB.prepare(`SELECT * FROM invites ORDER BY active DESC, created_at DESC LIMIT 50`).all();
        return ok({ items: results });
      }
      const { results } = await env.DB.prepare(`SELECT * FROM invites WHERE owner_id = ? ORDER BY created_at DESC LIMIT 20`).bind(user.id).all();
      return ok({ items: results, scope: 'self' });
    }
    if (path === 'invites' && method === 'POST') {
      const b = await request.json().catch(() => ({}));
      let code = '';
      let ownerId = 0;
      if (isAdmin(user)) {
        code = 'CY' + randHex(2).toUpperCase() + randHex(2).toUpperCase();
      } else {
        // 成员子码：渠道号前缀（如 CY001）+ 随机两位，可无限裂变
        const prefix = (user.channel_code || 'CY' + String(user.id).padStart(3, '0')).toUpperCase();
        for (let i = 0; i < 5; i++) {
          const cand = prefix + '-' + randHex(2).toUpperCase();
          const ex = await env.DB.prepare(`SELECT code FROM invites WHERE code = ?`).bind(cand).first();
          if (!ex) { code = cand; break; }
        }
        if (!code) return fail('子码生成失败，请重试');
        ownerId = user.id;
      }
      await env.DB.prepare(`INSERT INTO invites (code, note, owner_id) VALUES (?, ?, ?)`)
        .bind(code, clean(b.note, 64) || (ownerId ? '成员 ' + user.name + ' 的裂变子码' : ''), ownerId).run();
      return ok({ code, owner_id: ownerId });
    }
    if (seg[0] === 'invites' && seg.length === 2 && method === 'DELETE') {
      if (isAdmin(user)) {
        await env.DB.prepare(`DELETE FROM invites WHERE code = ?`).bind(seg[1]).run();
        return ok();
      }
      const r = await env.DB.prepare(`DELETE FROM invites WHERE code = ? AND owner_id = ?`).bind(seg[1], user.id).run();
      if (!r.meta.changes) return fail('只能删除自己生成的邀请码', 403);
      return ok();
    }

    // 工作日志
    if (path === 'logs' && method === 'GET') return await listLogs(env, user);
    if (path === 'logs' && method === 'POST') {
      const b = await request.json();
      const content = clean(b.content, 8000);
      if (!content) return fail('日志内容不能为空');
      const date = clean(b.log_date, 10) || new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
      const r = await env.DB.prepare(
        `INSERT INTO daily_logs (user_id, log_date, done, plan, issue, content) VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(user.id, date, clean(b.done, 4000), clean(b.plan, 4000), clean(b.issue, 2000), content)
        .run();
      return ok({ id: r.meta.last_row_id });
    }

    // 账号台账
    if (path === 'accounts' && method === 'GET') { if (!isAdmin(user)) return fail('运营台账仅管理员可见', 403); return await listAccounts(env); }
    if (path === 'accounts' && method === 'POST') { if (!isAdmin(user)) return fail('运营台账仅管理员可维护', 403);
      const b = await request.json();
      if (!clean(b.platform, 32) || !clean(b.account_name, 64)) return fail('平台和账号名必填');
      const r = await env.DB.prepare(
        `INSERT INTO account_ledger (owner_id, platform, account_name, url, category, status, fans, note)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(user.id, clean(b.platform, 32), clean(b.account_name, 64), clean(b.url, 300), clean(b.category, 16) || '社媒', clean(b.status, 16) || '运营中', clean(b.fans, 32), clean(b.note, 1000))
        .run();
      return ok({ id: r.meta.last_row_id });
    }

    // 客户
    if (path === 'customers' && method === 'GET') return await listCustomers(env, user);
    if (path === 'customers' && method === 'POST') {
      const b = await request.json();
      if (!clean(b.name, 64)) return fail('客户名称必填');
      const today = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
      // 滚动保护：归属跟着订单走。首次报备起 90 天，之后每次客户成交/续费自动顺延 90 天——
      // 客户一直消费就一直算报备人的；彻底沉默 90 天才回公海。不是"固定90天一刀切"。
      const protectedUntil = new Date(Date.now() + 8 * 3600 * 1000 + 90 * 86400 * 1000).toISOString().slice(0, 10);
      const sourceAgent = Number(b.source_agent_id) || user.id;
      const chCode = clean(b.channel_code, 32) || user.channel_code || '';
      const bizLine = clean(b.biz_line, 32) || '算力';
      // 归属冲突检查：同手机号/公司已被他人报备且在保护期内 → 拒绝，以首次报备为准
      const phone = clean(b.phone, 32);
      if (phone) {
        // 防伪装：客户手机号不能是内部成员（推广员）预留的手机号，防止自己报自己套佣金
        const dupAgent = await env.DB.prepare(`SELECT id, name FROM users WHERE phone = ? LIMIT 1`).bind(phone).first();
        if (dupAgent && !isAdmin(user))
          return fail('该手机号是内部成员预留号，不能作为客户报备（防套佣审核）', 409);
        const dup = await env.DB.prepare(
          `SELECT id, source_agent_id, protected_until FROM customers
            WHERE phone = ? AND id != 0 AND protected_until > date('now') ORDER BY id ASC LIMIT 1`
        ).bind(phone).first();
        if (dup && Number(dup.source_agent_id) !== sourceAgent && !isAdmin(user))
          return fail('该客户已由其他推广员报备且在保护期内，归属以首次报备为准', 409);
      }
      const r = await env.DB.prepare(
        `INSERT INTO customers (owner_id, name, company, contact, phone, wechat, industry, stage, amount, note,
           source_agent_id, report_date, channel_code, biz_line, protected_until)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(user.id, clean(b.name, 64), clean(b.company, 64), clean(b.contact, 32), phone, clean(b.wechat, 64), clean(b.industry, 32), clean(b.stage, 16) || '线索', clean(b.amount, 32), clean(b.note, 2000),
          sourceAgent, today, chCode, bizLine, protectedUntil)
        .run();
      await notifyAdmins(env, user.id, 'customer', '新客户报备：' + clean(b.name, 64), (clean(b.company, 64) || '') + ' · ' + bizLine + ' · ' + (clean(b.stage, 16) || '线索'), '/console?tab=customers');
      return ok({ id: r.meta.last_row_id });
    }

    // 通用：单条 id 操作
    if (seg.length === 2 && ['logs', 'accounts', 'customers', 'todos', 'files'].includes(seg[0])) {
      const table = { logs: 'daily_logs', accounts: 'account_ledger', customers: 'customers', todos: 'todos', files: 'files' }[seg[0]];
      const id = Number(seg[1]);
      if (!Number.isFinite(id)) return fail('参数错误');
      const ownerCol = seg[0] === 'accounts' || seg[0] === 'customers' ? 'owner_id' : 'user_id';
      const row = await env.DB.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
      if (!row) return fail('记录不存在', 404);
      if (!canEdit(user, row[ownerCol])) return fail('无权操作', 403);

      if (method === 'GET') return ok({ item: row });

      if (method === 'PUT') {
        const b = await request.json();
        const sets = [];
        const vals = [];
        const fields = {
          logs: { log_date: 10, done: 4000, plan: 4000, issue: 2000, content: 8000 },
          accounts: { platform: 32, account_name: 64, url: 300, category: 16, status: 16, fans: 32, note: 1000 },
          customers: { name: 64, company: 64, contact: 32, phone: 32, wechat: 64, industry: 32, stage: 16, amount: 32, note: 2000 },
          todos: { title: 120, detail: 2000, due_date: 10, priority: 8 },
          files: { title: 120, url: 2000, note: 1000 },
        }[seg[0]];
        for (const [k, max] of Object.entries(fields)) {
          if (b[k] !== undefined) {
            sets.push(`${k} = ?`);
            vals.push(clean(b[k], max));
          }
        }
        if (seg[0] === 'todos' && b.done !== undefined) {
          sets.push('done = ?');
          vals.push(boolInt(b.done));
          sets.push('done_at = ?');
          vals.push(b.done ? new Date().toISOString() : null);
        }
        if (seg[0] !== 'todos' && seg[0] !== 'files') {
          sets.push('updated_at = datetime(\'now\')');
        }
        // 滚动保护：客户状态改成"已成交"= 有真实消费/续费 → 归属窗口自动顺延 90 天
        if (seg[0] === 'customers' && b.stage !== undefined && b.stage === '已成交' && row.stage !== '已成交') {
          sets.push(`protected_until = date('now', '+90 day')`);
          // 推荐奖即时反馈：新势力首单成交 → 通知合伙人（30 元推荐奖按此发，防拉人头只算注册不算成果）
          try {
            const ag = await env.DB.prepare(`SELECT id, name, parent_id FROM users WHERE id = ?`).bind(Number(row.source_agent_id) || 0).first();
            if (ag && Number(ag.parent_id) > 0) {
              const prior = await env.DB.prepare(`SELECT COUNT(*) AS n FROM customers WHERE source_agent_id = ? AND stage = '已成交' AND id != ?`)
                .bind(Number(row.source_agent_id), id).first();
              const isFirst = !prior || Number(prior.n) === 0;
              await notify(env, Number(ag.parent_id), 'invite',
                (isFirst ? '🎉 新势力首单！' : '新势力出单：') + ag.name + ' · ' + (row.name || ''),
                (isFirst ? ag.name + ' 拿下第一单（' + (row.name || '') + '，' + (row.biz_line || '算力') + '）。按规则你拿推荐奖 30 元——记得在群里带上他。' : ag.name + ' 又成交一单（' + (row.name || '') + '），团队流水 +1。'),
                '/console?tab=sales');
            }
          } catch (e) { /* 通知失败不影响成交 */ }
        }
        if (!sets.length) return fail('没有要更新的字段');
        vals.push(id);
        await env.DB.prepare(`UPDATE ${table} SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
        return ok();
      }

      if (method === 'DELETE') {
        if (seg[0] === 'files') await env.DB.prepare(`DELETE FROM file_blobs WHERE file_id = ?`).bind(id).run();
        if (seg[0] === 'customers') await env.DB.prepare(`DELETE FROM customer_notes WHERE customer_id = ?`).bind(id).run();
        await env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
        return ok();
      }
    }

    // 客户备注
    if (seg[0] === 'customers' && seg[2] === 'notes' && method === 'GET') {
      const cid = Number(seg[1]);
      const c = await env.DB.prepare(`SELECT * FROM customers WHERE id = ?`).bind(cid).first();
      if (!c) return fail('客户不存在', 404);
      if (!canEdit(user, c.owner_id)) return fail('无权查看', 403);
      const { results } = await env.DB.prepare(
        `SELECT n.*, u.name AS user_name FROM customer_notes n JOIN users u ON u.id = n.user_id WHERE n.customer_id = ? ORDER BY n.id DESC`
      )
        .bind(cid)
        .all();
      return ok({ items: results });
    }
    if (seg[0] === 'customers' && seg[2] === 'notes' && method === 'POST') {
      const cid = Number(seg[1]);
      const c = await env.DB.prepare(`SELECT * FROM customers WHERE id = ?`).bind(cid).first();
      if (!c) return fail('客户不存在', 404);
      if (!canEdit(user, c.owner_id)) return fail('无权操作', 403);
      const b = await request.json();
      if (!clean(b.content, 2000)) return fail('内容不能为空');
      await env.DB.prepare(`INSERT INTO customer_notes (customer_id, user_id, content) VALUES (?, ?, ?)`)
        .bind(cid, user.id, clean(b.content, 2000))
        .run();
      await env.DB.prepare(`UPDATE customers SET updated_at = datetime('now') WHERE id = ?`).bind(cid).run();
      return ok();
    }

    // 待办
    if (path === 'todos' && method === 'GET') {
      const all = url.searchParams.get('all') === '1' && isAdmin(user);
      const { results } = all
        ? await env.DB.prepare(
            `SELECT t.*, u.name AS owner_name FROM todos t JOIN users u ON u.id = t.user_id ORDER BY t.done ASC, t.due_date ASC LIMIT 300`
          ).all()
        : await env.DB.prepare(`SELECT * FROM todos WHERE user_id = ? ORDER BY done ASC, due_date ASC LIMIT 300`).bind(user.id).all();
      return ok({ items: results });
    }
    if (path === 'todos' && method === 'POST') {
      const b = await request.json();
      if (!clean(b.title, 120)) return fail('标题不能为空');
      const r = await env.DB.prepare(`INSERT INTO todos (user_id, title, detail, due_date, priority) VALUES (?, ?, ?, ?, ?)`)
        .bind(user.id, clean(b.title, 120), clean(b.detail, 2000), clean(b.due_date, 10), clean(b.priority, 8) || '普通')
        .run();
      return ok({ id: r.meta.last_row_id });
    }

    // 公告
    if (path === 'announcements' && method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT a.*, u.name AS user_name FROM announcements a JOIN users u ON u.id = a.user_id ORDER BY a.pinned DESC, a.id DESC LIMIT 100`
      ).all();
      return ok({ items: results });
    }
    if (path === 'announcements' && method === 'POST') {
      if (!isAdmin(user)) return fail('仅管理员可发公告', 403);
      const b = await request.json();
      if (!clean(b.title, 120) || !clean(b.content, 5000)) return fail('标题和内容必填');
      await env.DB.prepare(`INSERT INTO announcements (user_id, title, content, pinned) VALUES (?, ?, ?, ?)`)
        .bind(user.id, clean(b.title, 120), clean(b.content, 5000), boolInt(b.pinned))
        .run();
      const { results: allUsers } = await env.DB.prepare(`SELECT id FROM users WHERE status = 'active'`).all();
      await Promise.all(allUsers.filter(u => u.id !== user.id).map(u =>
        notify(env, u.id, 'announcement', clean(b.title, 120), clean(b.content, 120), '/console?tab=news')
      ));
      return ok();
    }
    if (seg[0] === 'announcements' && seg.length === 2 && method === 'DELETE') {
      if (!isAdmin(user)) return fail('仅管理员可删除', 403);
      await env.DB.prepare(`DELETE FROM announcements WHERE id = ?`).bind(Number(seg[1])).run();
      return ok();
    }

    // 评论（协作）
    if (path === 'comments' && method === 'GET') {
      const t = url.searchParams.get('type');
      const id = Number(url.searchParams.get('id'));
      if (!t || !id) return fail('参数缺失');
      const { results } = await env.DB.prepare(
        `SELECT c.*, u.name AS user_name FROM comments c JOIN users u ON u.id = c.user_id
          WHERE c.target_type = ? AND c.target_id = ? ORDER BY c.id ASC`
      )
        .bind(t, id)
        .all();
      return ok({ items: results });
    }
    if (path === 'comments' && method === 'POST') {
      const b = await request.json();
      const t = clean(b.type, 16);
      const id = Number(b.id);
      if (!t || !id || !clean(b.content, 1000)) return fail('参数缺失');
      await env.DB.prepare(`INSERT INTO comments (target_type, target_id, user_id, content) VALUES (?, ?, ?, ?)`)
        .bind(t, id, user.id, clean(b.content, 1000))
        .run();
      return ok();
    }

    // 资料 / 附件
    if (path === 'files' && method === 'GET') {
      // 密级：public 全员可见（报价单/物料等），internal 仅管理员（合同/结算/成本）
      const boss = isAdmin(user);
      const { results } = await env.DB.prepare(
        `SELECT f.*, u.name AS user_name FROM files f JOIN users u ON u.id = f.user_id${boss ? '' : ` WHERE f.visibility = 'public'`} ORDER BY f.id DESC LIMIT 300`
      ).all();
      return ok({ items: results, scope: boss ? 'all' : 'public' });
    }
    if (path === 'files' && method === 'POST') {
      if (!isAdmin(user)) return fail('共享资料仅管理员可上传', 403);
      const b = await request.json();
      const vis = b.visibility === 'internal' ? 'internal' : 'public';
      const title = clean(b.title, 120) || '未命名';
      let kind = 'link';
      let fileId = 0;
      if (typeof b.dataUrl === 'string' && b.dataUrl.startsWith('data:')) {
        const m = b.dataUrl.match(/^data:([^;]+);base64,(.+)$/s);
        if (!m) return fail('图片格式不支持');
        const mime = m[1];
        if (!/^image\//.test(mime)) return fail('目前支持图片上传（其他文件请用链接）');
        const bin = atob(m[2]);
        if (bin.length > MAX_IMG) return fail('图片超过 900KB，请压缩后再传');
        kind = 'image';
        const res = await env.DB.prepare(`INSERT INTO files (user_id, title, kind, url, note, visibility) VALUES (?, ?, ?, '', ?, ?)`)
          .bind(user.id, title, kind, clean(b.note, 1000), vis)
          .run();
        fileId = res.meta.last_row_id;
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        await env.DB.prepare(`INSERT INTO file_blobs (file_id, mime, data) VALUES (?, ?, ?)`)
          .bind(fileId, mime, bytes.buffer)
          .run();
        await env.DB.prepare(`UPDATE files SET url = ? WHERE id = ?`).bind(`/api/files/${fileId}/raw`, fileId).run();
        return ok({ id: fileId });
      }
      if (!clean(b.url, 2000)) return fail('请填写链接或上传图片');
      const res = await env.DB.prepare(`INSERT INTO files (user_id, title, kind, url, note, visibility) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(user.id, title, 'link', clean(b.url, 2000), clean(b.note, 1000), vis)
        .run();
      return ok({ id: res.meta.last_row_id });
    }
    // 管理员切换单份资料的公开范围
    if (path === 'file-visibility' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const vis = b.visibility === 'internal' ? 'internal' : 'public';
      await env.DB.prepare(`UPDATE files SET visibility = ? WHERE id = ?`).bind(vis, Number(b.id)).run();
      return ok({ visibility: vis });
    }
    if (seg[0] === 'files' && seg[2] === 'raw' && method === 'GET') {
      const id = Number(seg[1]);
      const meta = await env.DB.prepare(`SELECT visibility FROM files WHERE id = ?`).bind(id).first();
      if (!meta) return fail('文件不存在', 404);
      if (!isAdmin(user) && meta.visibility !== 'public') return fail('该文件仅管理员可查看', 403);
      const row = await env.DB.prepare(`SELECT mime, data FROM file_blobs WHERE file_id = ?`).bind(id).first();
      if (!row) return fail('文件不存在', 404);
      const d = row.data;
      let body = d;
      if (ArrayBuffer.isView(d)) body = d;
      else if (Array.isArray(d)) body = new Uint8Array(d);
      else if (typeof d === 'string') body = new TextEncoder().encode(d);
      return new Response(body, {
        headers: {
          'content-type': row.mime,
          'content-length': String(d && d.byteLength != null ? d.byteLength : body && body.byteLength != null ? body.byteLength : -1),
          'cache-control': 'private, max-age=86400',
        },
      });
    }

    // ---------- 推广体系 ----------
    // 推广员/合伙人列表（含业绩汇总）
    if (path === 'agents' && method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT u.id, u.name, u.username, u.role_type, u.parent_id, u.channel_code, u.commission_rate, u.title, u.phone, u.team_no,
                p.name AS parent_name,
                (SELECT COUNT(*) FROM customers c WHERE c.source_agent_id = u.id) AS customer_count,
                (SELECT COUNT(*) FROM customers c WHERE c.source_agent_id = u.id AND c.stage = '已成交') AS closed_count
           FROM users u LEFT JOIN users p ON p.id = u.parent_id
          WHERE u.status = 'active' AND (u.role_type IN ('agent','leader') OR u.role = 'admin')
          ORDER BY u.role_type DESC, u.id ASC`
      ).all();
      return ok({ items: results });
    }
    // 设置某人为推广员/合伙人、指定上级与渠道码（仅管理员）
    if (path === 'agents' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const id = Number(b.id);
      const roleType = clean(b.role_type, 16) || 'agent';
      if (!['agent', 'leader', 'staff'].includes(roleType)) return fail('角色无效');
      if (!id) return fail('请选择成员');
      await env.DB.prepare(
        `UPDATE users SET role_type = ?, parent_id = ?, channel_code = ?, commission_rate = ? WHERE id = ?`
      ).bind(roleType, Number(b.parent_id) || 0, clean(b.channel_code, 32), Number(b.commission_rate) || 0.4, id).run();
      return ok();
    }
    // 佣金规则
    if (path === 'commission/rules' && method === 'GET') {
      const { results } = await env.DB.prepare(`SELECT * FROM commission_rules ORDER BY biz_line, tier`).all();
      return ok({ items: results });
    }
    if (path === 'commission/rules' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const rate = Number(b.rate);
      if (!clean(b.biz_line, 32) || !clean(b.tier, 32) || !(rate >= 0 && rate <= 1)) return fail('参数错误');
      await env.DB.prepare(
        `INSERT INTO commission_rules(biz_line, tier, rate, note) VALUES(?, ?, ?, ?)
         ON CONFLICT(biz_line, tier) DO UPDATE SET rate = excluded.rate, note = excluded.note, updated_at = datetime('now')`
      ).bind(clean(b.biz_line, 32), clean(b.tier, 32), rate, clean(b.note, 200)).run();
      return ok();
    }
    // 佣金看板：推广员看自己+下线，合伙人看本组，老板看全部
    if (path === 'commission' && method === 'GET') {
      const isBoss = isAdmin(user);
      const isLeader = user.role_type === 'leader';
      let where = '1=1', args = [];
      if (isBoss) { where = '1=1'; }
      else if (isLeader) { where = '(c.agent_id = ? OR u.parent_id = ?)'; args = [user.id, user.id]; }
      else { where = 'c.agent_id = ?'; args = [user.id]; }
      const { results: rows } = await env.DB.prepare(
        `SELECT c.*, u.name AS agent_name, u.parent_id FROM commissions c JOIN users u ON u.id = c.agent_id
          WHERE ${where} ORDER BY c.month DESC, c.id DESC LIMIT 300`
      ).bind(...args).all();
      const { results: totals } = await env.DB.prepare(
        `SELECT c.agent_id, u.name AS agent_name, u.team_no, SUM(c.amount) AS total, SUM(c.gross) AS gross
           FROM commissions c JOIN users u ON u.id = c.agent_id WHERE ${where} GROUP BY c.agent_id ORDER BY total DESC`
      ).bind(...args).all();
      return ok({ items: rows, totals, view: isBoss ? 'all' : isLeader ? 'team' : 'self' });
    }
    // 共享计佣核心：lines = [{agent_id, biz_line, tier, gross}]（gross=流水）。
    // 预估（报备数据）和核账（共绩结算单实数）都走这里，保证口径完全一致。
    async function applyCommissions(month, lines, tag) {
      const { results: rules } = await env.DB.prepare(`SELECT * FROM commission_rules`).all();
      const ruleMap = {};
      rules.forEach(r => ruleMap[r.biz_line + '|' + r.tier] = r.rate);
      const { results: users } = await env.DB.prepare(`SELECT id, parent_id FROM users`).all();
      const parentOf = {}; users.forEach(u => parentOf[u.id] = Number(u.parent_id) || 0);
      const agg = {};
      const teamAgg = {}; // 达标合伙人的直接下级流水
      const teamKids = {}; // 每个合伙人的直接下级（有流水的）数
      for (const c of lines) {
        const flow = Number(c.gross) || 0;
        if (!flow) continue;
        const key = Number(c.agent_id);
        if (!agg[key]) agg[key] = {};
        const tier = c.tier === '续费' ? '续费' : '常规';
        const rate = ruleMap[c.biz_line + '|' + tier] ?? 0.03; // 一律按规则表，废弃旧的 commission_rate 毛利口径（0.4 之类不能再当流水费率用）
        const lk = c.biz_line + '|' + tier;
        if (!agg[key][lk]) agg[key][lk] = { biz_line: c.biz_line, tier, gross: 0, amount: 0, rate };
        agg[key][lk].gross += flow;
        agg[key][lk].amount += flow * rate;
        const pid = parentOf[key];
        if (pid > 0 && pid !== key) {
          teamAgg[pid] = (teamAgg[pid] || 0) + flow;
          if (!teamKids[pid]) teamKids[pid] = new Set();
          teamKids[pid].add(key);
        }
      }
      // 合伙人门槛：直接下级≥2人 且 团队当月流水≥5000。达标者"吃底下"——
      // 从每个直接下级的佣金里划 25% 给合伙人（下级每挣4块合伙人拿1块），公司零成本，这才是海居模式。
      // 注意不能按"流水1%"划：算力佣金才3%，划流水1%等于把下级三分之一佣金划走，没人愿意被带你。
      const qualified = {};
      for (const [pid, flow] of Object.entries(teamAgg)) {
        const kids = (teamKids[pid] || new Set()).size;
        if (kids >= 2 && flow >= 5000) qualified[Number(pid)] = { flow, kids };
      }
      let n = 0;
      const leaderCut = {}; // 每个达标合伙人实际收到的划拨金额
      await env.DB.prepare(`DELETE FROM commissions WHERE month = ? AND status = '待结算'`).bind(month).run();
      for (const [aid, linesMap] of Object.entries(agg)) {
        const taxed = qualified[parentOf[Number(aid)]] ? true : false; // 我的上级达标 → 我上缴佣金的25%给他
        for (const v of Object.values(linesMap)) {
          const cut = taxed ? Math.round(v.amount * 25) / 100 : 0; // 下级佣金的25%
          if (taxed) leaderCut[parentOf[Number(aid)]] = (leaderCut[parentOf[Number(aid)]] || 0) + cut;
          await env.DB.prepare(
            `INSERT INTO commissions(agent_id, month, biz_line, gross, rate, amount, note) VALUES(?, ?, ?, ?, ?, ?, ?)`
          ).bind(Number(aid), month, v.biz_line, Math.round(v.gross * 100) / 100, v.rate, Math.round((v.amount - cut) * 100) / 100,
            tag + (v.tier === '续费' ? '续费月' : '首月') + (taxed ? '（已划拨团队25%）' : '')).run();
          n++;
        }
      }
      // 合伙人收入：从下级佣金划拨的 25% 汇总
      for (const [pid, q] of Object.entries(qualified)) {
        const f = Math.round(q.flow * 100) / 100;
        const amt = Math.round((leaderCut[Number(pid)] || 0) * 100) / 100;
        await env.DB.prepare(
          `INSERT INTO commissions(agent_id, month, biz_line, gross, rate, amount, note) VALUES(?, ?, '团队提成', ?, 0.25, ?, ?)`
        ).bind(Number(pid), month, f, amt, tag + '合伙人津贴·吃底下（下级' + q.kids + '人·各划佣金25%）').run();
        n++;
      }
      return n;
    }
    // 佣金生成（仅管理员）：按工作台报备的"客户实付流水 × 规则费率"计佣。
    // 注意：这是推广员报备的【预估数】——客户真实消费在共绩平台，我们看不到明细，
    // 正式佣金以甲方月度结算单的实际流水核账为准（commission/reconcile），多退少补。
    if (path === 'commission/generate' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const month = clean(b.month, 7) || new Date().toISOString().slice(0, 7);
      const { results: custs } = await env.DB.prepare(
        `SELECT c.*, u.commission_rate, u.parent_id, u.name AS agent_name FROM customers c JOIN users u ON u.id = c.source_agent_id
          WHERE c.stage = '已成交' AND c.source_agent_id > 0 AND c.protected_until >= ?`
      ).bind(month + '-28').all();
      // 防套佣双保险：客户手机号与任何内部成员手机号相同的成交记录，不计佣（需管理员核查）
      const { results: memberPhones } = await env.DB.prepare(`SELECT phone FROM users WHERE phone != ''`).all();
      const phoneSet = new Set(memberPhones.map(x => x.phone));
      const lines = [];
      for (const c of custs) {
        if (c.phone && phoneSet.has(c.phone)) continue; // 内部手机号冒充客户 → 剔除
        const flow = Number(String(c.amount || '').replace(/[^0-9.]/g, '')) || 0;
        if (!flow) continue;
        const isRenew = c.report_date && c.report_date.slice(0, 7) < month;
        lines.push({ agent_id: c.source_agent_id, biz_line: c.biz_line, tier: isRenew ? '续费' : '常规', gross: flow });
      }
      const n = await applyCommissions(month, lines, '');
      return ok({ month, generated: n, basis: '预估（报备数据），待共绩结算单核账' });
    }
    // 结算单核账（仅管理员）：共绩月度结算单下来后，把【实际流水】按人/线录入重算。
    // 客户真实消费全在甲方平台，工作台只能拿到这个月度总数——这就是我们的财务系统与甲方数据的唯一对接点。
    if (path === 'commission/reconcile' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const month = clean(b.month, 7);
      if (!month || !Array.isArray(b.flows) || !b.flows.length) return fail('请提供月份和结算单流水明细');
      const lines = [];
      for (const f of b.flows) {
        const aid = Number(f.agent_id);
        const gross = Number(f.gross) || 0;
        if (!aid || !clean(f.biz_line, 32)) continue;
        lines.push({ agent_id: aid, biz_line: clean(f.biz_line, 32), tier: f.tier === '续费' ? '续费' : '常规', gross });
      }
      if (!lines.length) return fail('结算单明细没有有效数据');
      const n = await applyCommissions(month, lines, '核账后·');
      return ok({ month, generated: n, basis: '共绩结算单实际流水（多退少补后为准）' });
    }
    // 结算佣金（仅管理员）
    if (path === 'commission/settle' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const ids = Array.isArray(b.ids) ? b.ids : [Number(b.id)];
      if (!ids.length) return fail('请选择结算记录');
      for (const id of ids) {
        await env.DB.prepare(`UPDATE commissions SET status = '已结算' WHERE id = ? AND status = '待结算'`).bind(Number(id)).run();
      }
      return ok({ settled: ids.length });
    }
    // 离职继承：把离职推广员的客户整体移交给接手人（仅管理员）。企微的客户继承，在工作台里做。
    if (path === 'agent-handover' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const from = Number(b.from_id), to = Number(b.to_id);
      if (!from || !to || from === to) return fail('请选择离职人和接手人');
      const taker = await env.DB.prepare(`SELECT id, name FROM users WHERE id = ?`).bind(to).first();
      if (!taker) return fail('接手人不存在');
      const r = await env.DB.prepare(
        `UPDATE customers SET source_agent_id = ?, updated_at = datetime('now')
          WHERE source_agent_id = ? AND protected_until > date('now')`
      ).bind(to, from).run();
      await notifyAdmins(env, user.id, 'handover', '客户交接完成：' + (b.from_name || ('推广员#' + from)) + ' → ' + taker.name,
        '保护期内客户 ' + (r.meta.changes || 0) + ' 名已整体移交，后续续费佣金归接手人', '/console?tab=sales');
      return ok({ moved: r.meta.changes || 0, to: taker.name });
    }

    // ---------- 设置 ----------
    if (path === 'settings' && method === 'GET') {
      const keys = ['webhook_url', 'workspace_name', 'platforms'];
      const out = {};
      for (const k of keys) out[k] = await getSetting(env, k);
      out.seedImported = (await getSetting(env, 'seed_v2')) === '1';
      // 合伙人账号：脱敏，不给 webhook 与内部平台配置
      if (user.role !== 'admin') { out.webhook_url = ''; out.platforms = ''; }
      return ok({ settings: out });
    }
    if (path === 'settings' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      if (b.webhook_url !== undefined) {
        const v = clean(b.webhook_url, 500);
        if (v && !/^https:\/\//.test(v)) return fail('webhook 必须以 https:// 开头');
        await setSetting(env, 'webhook_url', v);
      }
      if (b.workspace_name !== undefined) await setSetting(env, 'workspace_name', clean(b.workspace_name, 60));
      if (b.platforms !== undefined) await setSetting(env, 'platforms', String(b.platforms || '').slice(0, 8000));
      return ok();
    }
    if (path === 'settings/webhook/test' && method === 'POST' && isAdmin(user)) {
      const hook = await getSetting(env, 'webhook_url');
      if (!hook) return fail('尚未配置 webhook 地址');
      const r = await fetch(hook, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ msgtype: 'text', text: { content: '【炽云AI工作台】通知测试：连接成功' } }),
      }).catch(() => null);
      if (!r || !r.ok) return fail('推送失败，请检查 webhook 地址');
      return ok();
    }
    if (path === 'seed' && method === 'POST') {
      const r = await importSeed(env);
      if (r.error) return fail(r.error, 500);
      return ok(r);
    }

    // ---------- 站内消息（内部沟通，合伙人不开放） ----------
    if (path === 'messages' && (method === 'GET' || method === 'POST') && !isAdmin(user)) return fail('站内消息仅内部使用', 403);
    if (path === 'messages' && method === 'GET') {
      const other = Number(url.searchParams.get('with') || 0);
      if (other) {
        await env.DB.prepare(`UPDATE messages SET read_at = datetime('now') WHERE from_id = ? AND to_id = ? AND read_at IS NULL`)
          .bind(other, user.id).run();
        const { results } = await env.DB.prepare(
          `SELECT m.*, f.name AS from_name, t.name AS to_name FROM messages m
           JOIN users f ON f.id = m.from_id JOIN users t ON t.id = m.to_id
           WHERE (m.from_id = ? AND m.to_id = ?) OR (m.from_id = ? AND m.to_id = ?)
           ORDER BY m.id ASC LIMIT 300`
        ).bind(user.id, other, other, user.id).all();
        return ok({ items: results });
      }
      const { results } = await env.DB.prepare(
        `SELECT m.id, m.from_id, m.to_id, m.content, m.created_at, m.read_at,
                f.name AS from_name, t.name AS to_name
           FROM messages m JOIN users f ON f.id = m.from_id JOIN users t ON t.id = m.to_id
           WHERE m.id IN (
             SELECT MAX(id) FROM messages WHERE from_id = ? OR to_id = ? GROUP BY
               CASE WHEN from_id = ? THEN to_id ELSE from_id END
           ) ORDER BY m.id DESC LIMIT 100`
      ).bind(user.id, user.id, user.id).all();
      const unread = await env.DB.prepare(
        `SELECT from_id AS uid, COUNT(*) AS n FROM messages WHERE to_id = ? AND read_at IS NULL GROUP BY from_id`
      ).bind(user.id).all();
      const umap = {}; (unread.results || []).forEach(r => umap[r.uid] = r.n);
      const { results: peers } = await env.DB.prepare(`SELECT id, name, title FROM users WHERE status = 'active' AND id != ? ORDER BY id`).bind(user.id).all();
      return ok({ items: results, unread: umap, peers });
    }
    if (path === 'messages' && method === 'POST') {
      const b = await request.json();
      const toId = Number(b.to_id);
      const content = clean(b.content, 2000);
      if (!toId || !content) return fail('收件人与内容必填');
      const target = await env.DB.prepare(`SELECT id, name FROM users WHERE id = ? AND status = 'active'`).bind(toId).first();
      if (!target) return fail('收件人不存在', 404);
      const r = await env.DB.prepare(`INSERT INTO messages(from_id, to_id, content) VALUES(?, ?, ?)`)
        .bind(user.id, toId, content).run();
      await notify(env, toId, 'message', user.name + ' 发来消息', content.slice(0, 100), '/console?tab=messages&with=' + user.id);
      return ok({ id: r.meta.last_row_id });
    }

    // ---------- 审批流程 ----------
    if (path === 'approvals' && method === 'GET') {
      const scope = url.searchParams.get('scope') || 'all';
      let sql = `SELECT a.*, u.name AS applicant_name, v.name AS approver_name FROM approvals a
                 JOIN users u ON u.id = a.applicant_id JOIN users v ON v.id = a.approver_id`;
      let rows;
      if (scope === 'mine') rows = await env.DB.prepare(sql + ` WHERE a.applicant_id = ? ORDER BY a.id DESC LIMIT 200`).bind(user.id).all();
      else if (scope === 'todo') rows = await env.DB.prepare(sql + ` WHERE a.approver_id = ? AND a.status = '待审批' ORDER BY a.id DESC LIMIT 200`).bind(user.id).all();
      else if (scope === 'done' && isAdmin(user)) rows = await env.DB.prepare(sql + ` WHERE a.status != '待审批' ORDER BY a.id DESC LIMIT 200`).all();
      else rows = await env.DB.prepare(sql + ` WHERE a.applicant_id = ? OR a.approver_id = ? OR ? = 1 ORDER BY a.id DESC LIMIT 200`).bind(user.id, user.id, isAdmin(user) ? 1 : 0).all();
      return ok({ items: rows.results });
    }
    if (path === 'approvals' && method === 'POST') {
      const b = await request.json();
      const title = clean(b.title, 120);
      const content = clean(b.content, 3000);
      if (!title || !content) return fail('标题与内容必填');
      const approverId = Number(b.approver_id) || await firstAdminId(env);
      const r = await env.DB.prepare(
        `INSERT INTO approvals(applicant_id, approver_id, kind, title, content, amount) VALUES(?, ?, ?, ?, ?, ?)`
      ).bind(user.id, approverId, clean(b.kind, 32) || '通用申请', title, content, clean(b.amount, 32)).run();
      await notify(env, approverId, 'approval', '待审批：' + title, user.name + ' 提交了申请，请及时处理', '/console?tab=approvals&scope=todo');
      return ok({ id: r.meta.last_row_id });
    }
    if (seg[0] === 'approvals' && seg.length === 2 && method === 'GET') {
      const r = await env.DB.prepare(
        `SELECT a.*, u.name AS applicant_name, v.name AS approver_name FROM approvals a
         JOIN users u ON u.id = a.applicant_id JOIN users v ON v.id = a.approver_id WHERE a.id = ?`
      ).bind(Number(seg[1])).first();
      if (!r) return fail('记录不存在', 404);
      return ok({ item: r });
    }
    if (seg[0] === 'approvals' && seg.length === 2 && method === 'PUT') {
      const r = await env.DB.prepare(`SELECT * FROM approvals WHERE id = ?`).bind(Number(seg[1])).first();
      if (!r) return fail('记录不存在', 404);
      const b = await request.json();
      const status = clean(b.status, 16);
      if (!['通过', '驳回', '撤回'].includes(status)) return fail('状态无效');
      if (status !== '撤回' && Number(r.approver_id) !== user.id && !isAdmin(user)) return fail('只有审批人可以操作', 403);
      if (status === '撤回' && Number(r.applicant_id) !== user.id) return fail('只有申请人可以撤回', 403);
      if (r.status !== '待审批') return fail('该申请已处理');
      await env.DB.prepare(`UPDATE approvals SET status = ?, handle_note = ?, handled_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`)
        .bind(status, clean(b.handle_note, 500), r.id).run();
      await notify(env, r.applicant_id, 'approval', '审批' + status + '：' + r.title, (b.handle_note ? '备注：' + clean(b.handle_note, 100) : '你的申请已处理'), '/console?tab=approvals&scope=mine');
      return ok();
    }

    // ---------- 站内通知 ----------
    if (path === 'notifications' && method === 'GET') {
      const { results } = await env.DB.prepare(`SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100`).bind(user.id).all();
      const u = await env.DB.prepare(`SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0`).bind(user.id).first();
      return ok({ items: results, unread: u.n });
    }
    if (path === 'notifications/read' && method === 'POST') {
      const b = await request.json();
      if (b.id) await env.DB.prepare(`UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?`).bind(Number(b.id), user.id).run();
      else await env.DB.prepare(`UPDATE notifications SET read = 1 WHERE user_id = ?`).bind(user.id).run();
      return ok();
    }

    // ---------- 知识资料（密级：public 对合伙人可见，internal 仅管理员）----------
    if (path === 'docs' && method === 'GET') {
      const boss = isAdmin(user);
      const cat = clean(url.searchParams.get('category'), 32);
      const q = clean(url.searchParams.get('q'), 60);
      let sql = `SELECT id, title, category, summary, source, tags, visibility, created_at, length(content) AS size FROM docs`;
      const where = [], args = [];
      if (!boss) where.push(`visibility = 'public'`);
      if (cat) { where.push(`category = ?`); args.push(cat); }
      if (q) { where.push(`(title LIKE ? OR summary LIKE ? OR content LIKE ?)`); const k = '%' + q + '%'; args.push(k, k, k); }
      if (where.length) sql += ' WHERE ' + where.join(' AND ');
      sql += ` ORDER BY id DESC LIMIT 300`;
      const { results } = await env.DB.prepare(sql).bind(...args).all();
      const cats = await env.DB.prepare(
        `SELECT category, COUNT(*) AS n FROM docs${boss ? '' : ` WHERE visibility='public'`} GROUP BY category ORDER BY n DESC`
      ).all();
      return ok({ items: results, categories: cats.results, scope: boss ? 'all' : 'public' });
    }
    if (path === 'docs' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const title = clean(b.title, 120);
      if (!title) return fail('标题必填');
      const vis = b.visibility === 'public' ? 'public' : 'internal';
      await env.DB.prepare(`INSERT INTO docs(title, category, summary, content, source, tags, visibility) VALUES(?, ?, ?, ?, ?, ?, ?)`)
        .bind(title, clean(b.category, 32) || '综合', clean(b.summary, 500), clean(b.content, 8000), clean(b.source, 300), clean(b.tags, 200), vis).run();
      return ok();
    }
    // 管理员切换单份资料的公开范围（独立路径，避开 docs/:id 路由）
    if (path === 'doc-visibility' && method === 'POST' && isAdmin(user)) {
      const b = await request.json();
      const vis = b.visibility === 'public' ? 'public' : 'internal';
      await env.DB.prepare(`UPDATE docs SET visibility = ?, updated_at = datetime('now') WHERE id = ?`)
        .bind(vis, Number(b.id)).run();
      return ok({ visibility: vis });
    }
    if (seg[0] === 'docs' && seg.length === 2 && method === 'GET') {
      const r = await env.DB.prepare(`SELECT * FROM docs WHERE id = ?`).bind(Number(seg[1])).first();
      if (!r) return fail('资料不存在', 404);
      if (!isAdmin(user) && r.visibility !== 'public') return fail('该资料仅管理员可查看', 403);
      return ok({ item: r });
    }
    if (seg[0] === 'docs' && seg.length === 2 && method === 'DELETE' && isAdmin(user)) {
      await env.DB.prepare(`DELETE FROM docs WHERE id = ?`).bind(Number(seg[1])).run();
      return ok();
    }

    return fail('接口不存在: ' + path, 404);
  } catch (e) {
    return fail('服务异常：' + (e && e.message ? e.message : String(e)), 500);
  }
}
