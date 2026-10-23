require('dotenv').config();
const express = require('express'), Database = require('better-sqlite3'),
  bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), gw = require('./gateway');

const ADMIN = (process.env.ADMIN_EMAIL || 'igor4558600@gmail.com').toLowerCase().trim();
const SECRET = process.env.JWT_SECRET;
if (!SECRET) { console.error('Defina JWT_SECRET no arquivo .env'); process.exit(1); }
const TRIAL = +process.env.TRIAL_DAYS || 14, DAY = 864e5;
const PLANS = { mensal: { nome: 'Mensal', valor: +process.env.PRICE_MONTH || 49.9, dias: 30 } };

const db = new Database(process.env.DB_FILE || 'data.db');
db.pragma('journal_mode = WAL');
db.exec(`
create table if not exists users(id integer primary key, email text unique, name text, store text,
  cnpj text default '', logo text default '', pw text, trial_ends text, paid_until text,
  blocked integer default 0, created_at text default current_timestamp);
create table if not exists products(id integer primary key, user_id integer, name text, flavor text,
  exp text, qty integer, lot text, buy text, dist text, img text, gtin text default '',
  created_at text default current_timestamp);
create table if not exists payments(id integer primary key, user_id integer, gateway text, ref text,
  status text, amount real, created_at text default current_timestamp);
create index if not exists ix_p_user on products(user_id);`);

// Conta admin criada/atualizada na inicialização com ADMIN_PASSWORD (ninguém mais consegue se cadastrar com esse e-mail)
if (process.env.ADMIN_PASSWORD) {
  db.prepare(`insert into users(email,name,store,pw,trial_ends) values(?,?,?,?,?)
    on conflict(email) do update set pw=excluded.pw`)
    .run(ADMIN, 'Igor', 'Administração', bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10), new Date().toISOString());
} else console.warn('Atenção: defina ADMIN_PASSWORD para criar o acesso admin.');

const iso = t => new Date(t).toISOString();
const isAdmin = u => u.email === ADMIN;
const sign = id => jwt.sign({ id }, SECRET, { expiresIn: '30d' });

function access(u) {
  if (isAdmin(u)) return { ok: true, status: 'admin', days: null };
  if (u.blocked) return { ok: false, status: 'blocked', days: 0 };
  const now = Date.now(), paid = Date.parse(u.paid_until) || 0, trial = Date.parse(u.trial_ends) || 0;
  if (paid > now) return { ok: true, status: 'active', days: Math.ceil((paid - now) / DAY) };
  if (trial > now) return { ok: true, status: 'trial', days: Math.ceil((trial - now) / DAY) };
  return { ok: false, status: 'expired', days: 0 };
}
const pub = u => ({ id: u.id, email: u.email, name: u.name, store: u.store, cnpj: u.cnpj, logo: u.logo,
  role: isAdmin(u) ? 'admin' : 'user', access: access(u) });

function auth(req, res, next) {
  try {
    const p = jwt.verify((req.headers.authorization || '').slice(7), SECRET);
    const u = db.prepare('select * from users where id=?').get(p.id);
    if (!u) throw 0;
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Faça login novamente.' }); }
}
const paid = (req, res, next) => access(req.user).ok ? next()
  : res.status(402).json({ error: 'Seu acesso está encerrado. Assine para continuar.' });
const adm = (req, res, next) => isAdmin(req.user) ? next() : res.status(403).json({ error: 'Acesso negado.' });

const app = express();
app.use(express.json({ limit: '2mb', verify: (req, _res, buf) => { req.rawBody = buf; } })); // rawBody: p/ validar assinatura de webhook
app.use(express.static('public'));

// ---------- conta ----------
app.post('/api/register', (req, res) => {
  const { name, store, email, password } = req.body || {};
  const e = String(email || '').toLowerCase().trim();
  if (!name || !store || !e.includes('@') || String(password || '').length < 6)
    return res.status(400).json({ error: 'Preencha nome, loja, e-mail válido e senha (mínimo 6).' });
  if (e === ADMIN) return res.status(403).json({ error: 'Este e-mail é reservado.' });
  if (db.prepare('select 1 from users where email=?').get(e))
    return res.status(409).json({ error: 'Este e-mail já tem conta. Use Entrar.' });
  const r = db.prepare('insert into users(email,name,store,pw,trial_ends) values(?,?,?,?,?)')
    .run(e, String(name).trim().slice(0, 80), String(store).trim().slice(0, 80), bcrypt.hashSync(password, 10), iso(Date.now() + TRIAL * DAY));
  res.json({ token: sign(r.lastInsertRowid) });
});
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('select * from users where email=?').get(String(email || '').toLowerCase().trim());
  if (!u || !bcrypt.compareSync(String(password || ''), u.pw)) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  res.json({ token: sign(u.id) });
});
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));
app.put('/api/me', auth, (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.store) return res.status(400).json({ error: 'Nome e loja são obrigatórios.' });
  db.prepare('update users set name=?,store=?,cnpj=?,logo=? where id=?').run(
    String(b.name).slice(0, 80), String(b.store).slice(0, 80), String(b.cnpj || '').slice(0, 20),
    String(b.logo || '').startsWith('data:image/') ? b.logo : '', req.user.id);
  res.json(pub(db.prepare('select * from users where id=?').get(req.user.id)));
});

// ---------- produtos ----------
const D = /^\d{4}-\d{2}-\d{2}$/;
function clean(b) {
  const name = String(b.name || '').trim().slice(0, 120);
  if (!name || !D.test(b.exp || '') || !(+b.qty > 0)) return null;
  return { name, flavor: String(b.flavor || '').slice(0, 80), exp: b.exp, qty: Math.floor(+b.qty),
    lot: String(b.lot || '').slice(0, 60), buy: D.test(b.buy || '') ? b.buy : '', dist: String(b.dist || '').slice(0, 80),
    img: String(b.img || '').startsWith('data:image/') ? b.img : '', gtin: String(b.gtin || '').replace(/\D/g, '').slice(0, 14) };
}
const COLS = '@name,@flavor,@exp,@qty,@lot,@buy,@dist,@img,@gtin';
app.get('/api/products', auth, paid, (req, res) =>
  res.json(db.prepare('select * from products where user_id=? order by exp').all(req.user.id)));
app.post('/api/products', auth, paid, (req, res) => {
  const p = clean(req.body || {});
  if (!p) return res.status(400).json({ error: 'Informe nome, validade e quantidade.' });
  const r = db.prepare(`insert into products(user_id,name,flavor,exp,qty,lot,buy,dist,img,gtin) values(@u,${COLS})`).run({ ...p, u: req.user.id });
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/products/:id', auth, paid, (req, res) => {
  const p = clean(req.body || {});
  if (!p) return res.status(400).json({ error: 'Informe nome, validade e quantidade.' });
  db.prepare('update products set name=@name,flavor=@flavor,exp=@exp,qty=@qty,lot=@lot,buy=@buy,dist=@dist,img=@img,gtin=@gtin where id=@id and user_id=@u')
    .run({ ...p, id: +req.params.id, u: req.user.id });
  res.json({ ok: 1 });
});
app.delete('/api/products/:id', auth, paid, (req, res) => {
  db.prepare('delete from products where id=? and user_id=?').run(+req.params.id, req.user.id);
  res.json({ ok: 1 });
});

// código de barras (EAN) -> nome do produto: primeiro o histórico da própria loja, depois Open Food Facts
app.get('/api/lookup/:gtin', auth, paid, async (req, res) => {
  const g = req.params.gtin.replace(/\D/g, '');
  const own = db.prepare('select name,flavor,img from products where user_id=? and gtin=? order by id desc limit 1').get(req.user.id, g);
  if (own) return res.json(own);
  try {
    const r = await fetch(`https://world.openfoodfacts.org/api/v2/product/${g}.json?fields=product_name,brands`, { signal: AbortSignal.timeout(4000) });
    const p = (await r.json()).product || {};
    if (p.product_name) return res.json({ name: [p.product_name, (p.brands || '').split(',')[0]].filter(Boolean).join(' - '), flavor: '', img: '' });
  } catch { /* sem internet ou fora do ar: segue sem sugestão */ }
  res.json({});
});

// ---------- assinatura / pagamento ----------
function grant(uid, days, gateway, ref, amount) {
  const u = db.prepare('select paid_until from users where id=?').get(uid);
  if (!u) return;
  if (ref && db.prepare('select 1 from payments where gateway=? and ref=?').get(gateway, ref)) return; // não conta o mesmo pagamento 2x
  const base = Math.max(Date.now(), Date.parse(u.paid_until) || 0);
  db.prepare('update users set paid_until=?,blocked=0 where id=?').run(iso(base + days * DAY), uid);
  db.prepare('insert into payments(user_id,gateway,ref,status,amount) values(?,?,?,?,?)').run(uid, gateway, ref || '', 'paid', amount || 0);
}
app.get('/api/plans', (_req, res) => res.json(PLANS));
app.post('/api/billing/checkout', auth, async (req, res) => {
  const plan = PLANS[(req.body || {}).plan || 'mensal'];
  if (!plan) return res.status(400).json({ error: 'Plano inválido.' });
  try { res.json(await gw.createCheckout({ user: req.user, plan })); }
  catch (e) { res.status(501).json({ error: e.message }); }
});
// O gateway chama: POST /api/webhook/<nome>?token=WEBHOOK_SECRET
app.post('/api/webhook/:gateway', (req, res) => {
  if (!process.env.WEBHOOK_SECRET || req.query.token !== process.env.WEBHOOK_SECRET) return res.sendStatus(401);
  try {
    const ev = gw.parseWebhook(req);
    if (ev && ev.paid) {
      const uid = ev.userId || (db.prepare('select id from users where email=?').get(String(ev.email || '').toLowerCase()) || {}).id;
      if (uid) grant(uid, ev.days || PLANS.mensal.dias, req.params.gateway, ev.ref, ev.amount);
    }
    res.sendStatus(200);
  } catch (e) { console.error('webhook:', e.message); res.sendStatus(400); }
});

// ---------- admin ----------
app.get('/api/admin/users', auth, adm, (_req, res) =>
  res.json(db.prepare('select u.*,(select count(*) from products where user_id=u.id) n from users u order by u.id desc').all()
    .map(u => ({ ...pub(u), n: u.n, blocked: u.blocked, created: u.created_at }))));
app.get('/api/admin/products', auth, adm, (_req, res) =>
  res.json(db.prepare('select p.id,p.name,p.flavor,p.exp,p.qty,p.lot,p.dist,u.store from products p join users u on u.id=p.user_id order by p.exp').all()));
app.post('/api/admin/users/:id/grant', auth, adm, (req, res) => {
  grant(+req.params.id, +(req.body || {}).days || 30, 'admin', 'admin-' + Date.now(), 0); res.json({ ok: 1 });
});
app.post('/api/admin/users/:id/block', auth, adm, (req, res) => {
  db.prepare('update users set blocked=? where id=?').run((req.body || {}).blocked ? 1 : 0, +req.params.id); res.json({ ok: 1 });
});

app.listen(process.env.PORT || 3000, () => console.log('ValidaPro no ar: http://localhost:' + (process.env.PORT || 3000)));
