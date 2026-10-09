// Paperthreads backend: Express + JSON file storage (no database setup needed)
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'data.json');
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ---------- storage ----------
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const verify = (pw, stored) => hash(pw, stored.split(':')[0]) === stored;

// Data lives in PostgreSQL when DATABASE_URL is set (use this on Render / any host with a temporary disk).
// Without DATABASE_URL it falls back to the local data.json file (fine on your own PC).
const USE_PG = !!process.env.DATABASE_URL;
let pool = null;
let db = { users: [], orders: [], seq: 0 };
let writing = Promise.resolve(), saveError = null;

async function persist(snap) {
  if (USE_PG) {
    await pool.query(
      'INSERT INTO app_state (id, data, updated_at) VALUES (1, $1::jsonb, now()) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()',
      [snap]);
  } else fs.writeFileSync(DB_FILE, snap);
}
// writes are queued one after another so they can never overlap or arrive out of order
const save = () => {
  const snap = JSON.stringify(db);
  writing = writing.then(() => persist(snap)).then(() => { saveError = null; })
    .catch(e => { saveError = e; console.error('Save failed:', e.message); });
};
// a change is only confirmed to the browser after it has really been saved
app.use((req, res, next) => {
  if (req.method === 'GET') return next();
  const send = res.json.bind(res);
  res.json = body => {
    writing.then(() => {
      if (saveError) { res.status(500); return send({ error: 'Could not save to the database. Please try again.' }); }
      send(body);
    });
    return res;
  };
  next();
});

async function initDb() {
  if (USE_PG) {
    const { Pool } = require('pg');
    pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false } });
    pool.on('error', e => console.error('DB connection dropped (will reconnect):', e.message));
    await pool.query('CREATE TABLE IF NOT EXISTS app_state (id INT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())');
    const r = await pool.query('SELECT data FROM app_state WHERE id = 1');
    if (r.rows.length) db = r.rows[0].data;
    else if (fs.existsSync(DB_FILE)) { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); console.log('Imported existing data.json into the database'); }
    console.log('Using PostgreSQL database');
  } else {
    if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    console.log('Using local file ' + DB_FILE + ' (set DATABASE_URL to use a database)');
  }
  db.users = db.users || []; db.orders = db.orders || [];
  if (!db.users.length) {
    db.users.push({ id: crypto.randomUUID(), name: 'Admin', username: 'admin', role: 'admin', password: hash('admin123') });
    console.log('First run: login with admin / admin123 (change it in Users page)');
  }
  if (!db.secret) db.secret = crypto.randomBytes(32).toString('hex');
  save(); await writing;
  if (saveError) throw saveError;
}

// ---------- auth ----------
// login tokens are signed with a secret stored in the database, so people stay logged in after a restart
const publicUser = ({ password, ...u }) => u;
const sign = p => crypto.createHmac('sha256', db.secret).update(p).digest('hex');
const makeToken = uid => { const p = uid + '.' + (Date.now() + 30 * 864e5); return p + '.' + sign(p); };
function readToken(t) {
  const [uid, exp, sig] = String(t || '').split('.');
  if (!sig || +exp < Date.now()) return null;
  const good = sign(uid + '.' + exp);
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)) ? uid : null;
}
const auth = (req, res, next) => {
  const u = readToken((req.headers.authorization || '').replace('Bearer ', ''));
  req.user = u && db.users.find(x => x.id === u);
  if (!req.user) return res.status(401).json({ error: 'Please log in' });
  next();
};
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.users.find(x => x.username === username);
  if (!u || !verify(password || '', u.password)) return res.status(400).json({ error: 'Wrong username or password' });
  res.json({ token: makeToken(u.id), user: publicUser(u) });
});
app.post('/api/logout', auth, (req, res) => res.json({ ok: true }));
app.get('/api/me', auth, (req, res) => res.json(publicUser(req.user)));

// ---------- orders CRUD ----------
const num = v => Math.max(0, Number(v) || 0);
function cleanOrder(b) {
  const total = num(b.total), advance = Math.min(num(b.advance), total);
  return {
    orderNo: String(b.orderNo || '').trim(),
    customer: String(b.customer || '').trim(),
    phone: String(b.phone || '').trim(),
    item: String(b.item || '').trim(),
    size: String(b.size || '').trim(),
    total, advance, remaining: total - advance,
    orderDate: b.orderDate || new Date().toISOString().slice(0, 10),
    deadline: b.deadline || '',
    notes: String(b.notes || '').trim(),
    standRent: b.standRent === true || b.standRent === 'true',
    standFee: (b.standRent === true || b.standRent === 'true') ? num(b.standFee) : 0,
    paintRent: b.paintRent === true || b.paintRent === 'true',
    paintFee: (b.paintRent === true || b.paintRent === 'true') ? num(b.paintFee) : 0,
    address: String(b.address || '').trim(),
    payType: b.payType === 'cod' ? 'cod' : 'full', // full = pays everything before shipping, cod = advance now + balance on delivery
  };
}
const COURIER = ['Ready to ship', 'Handed to courier', 'In transit', 'Out for delivery', 'Delivered'];
const EDITABLE = ['Pending', 'In progress', 'Completed'];
const todayStr = () => new Date().toISOString().slice(0, 10);
const dupOf = (no, id) => db.orders.find(o => o.id !== id && o.orderNo.toLowerCase() === no.toLowerCase());
const dupMsg = d => 'Order number ' + d.orderNo + ' is already used (customer: ' + d.customer + ')';
// keep courier fields consistent with the order status
function syncCourier(o) {
  if (o.status === 'Completed') { if (!o.courierStatus || o.courierStatus === 'Delivered') o.courierStatus = 'Ready to ship'; delete o.deliveredAt; }
  else if (o.status === 'Delivered') { o.courierStatus = 'Delivered'; if (!o.deliveredAt) o.deliveredAt = todayStr(); }
  else { delete o.courierStatus; delete o.deliveredAt; }
}
app.get('/api/orders', auth, (req, res) => res.json(db.orders));
app.post('/api/orders', auth, (req, res) => {
  const o = cleanOrder(req.body);
  if (!o.orderNo) return res.status(400).json({ error: 'Order number is required' });
  if (!o.customer) return res.status(400).json({ error: 'Customer name is required' });
  const d1 = dupOf(o.orderNo); if (d1) return res.status(400).json({ error: dupMsg(d1) });
  // new orders always start as Pending; tracking number is added later from the Courier tab
  const order = { id: crypto.randomUUID(), ...o, trackingNo: '', status: 'Pending' };
  db.orders.push(order); save(); res.status(201).json(order);
});
app.put('/api/orders/:id', auth, (req, res) => {
  const was = db.orders.find(o => o.id === req.params.id);
  if (!was) return res.status(404).json({ error: 'Order not found' });
  const o = cleanOrder(req.body);
  if (!o.orderNo) return res.status(400).json({ error: 'Order number is required' });
  if (!o.customer) return res.status(400).json({ error: 'Customer name is required' });
  const d2 = dupOf(o.orderNo, was.id); if (d2) return res.status(400).json({ error: dupMsg(d2) });
  // full-payment customers must pay everything before the order is completed (COD customers pay the balance on delivery)
  if (req.body.status === 'Completed' && was.status !== 'Completed' && was.status !== 'Delivered' && o.payType === 'full' && o.remaining > 0)
    return res.status(400).json({ error: 'Full payment must be received before completing this order (balance ' + o.remaining + ')' });
  Object.assign(was, o); // trackingNo is not touched here, so editing never wipes it
  // Delivered is only set from the Courier tab, and can't be changed here
  if (was.status !== 'Delivered') was.status = EDITABLE.includes(req.body.status) ? req.body.status : was.status;
  syncCourier(was); save(); res.json(was);
});
// "Full payment" button: marks the whole balance as received
app.post('/api/orders/:id/pay', auth, (req, res) => {
  const o = db.orders.find(x => x.id === req.params.id);
  if (!o) return res.status(404).json({ error: 'Order not found' });
  o.advance = o.total; o.remaining = 0; o.paidAt = todayStr();
  save(); res.json(o);
});
// Courier tab: tracking number + courier status
app.patch('/api/orders/:id', auth, (req, res) => {
  const o = db.orders.find(x => x.id === req.params.id);
  if (!o) return res.status(404).json({ error: 'Order not found' });
  if (o.status !== 'Completed' && o.status !== 'Delivered') return res.status(400).json({ error: 'Only completed orders can go to the courier' });
  if (req.body.trackingNo !== undefined) o.trackingNo = String(req.body.trackingNo).trim();
  if (COURIER.includes(req.body.courierStatus)) {
    const was = o.status;
    o.courierStatus = req.body.courierStatus;
    o.status = o.courierStatus === 'Delivered' ? 'Delivered' : 'Completed';
    syncCourier(o);
    // COD: when the parcel is delivered the courier has collected the balance
    if (o.status === 'Delivered' && was !== 'Delivered' && o.payType === 'cod' && o.remaining > 0) {
      o.advanceBeforeCod = o.advance; o.advance = o.total; o.remaining = 0; o.codCollected = true; o.paidAt = todayStr();
    }
    // moved back out of Delivered: undo the COD collection
    if (o.status !== 'Delivered' && was === 'Delivered' && o.codCollected) {
      o.advance = o.advanceBeforeCod || 0; o.remaining = o.total - o.advance;
      delete o.codCollected; delete o.advanceBeforeCod; delete o.paidAt;
    }
  }
  save(); res.json(o);
});
app.delete('/api/orders/:id', auth, (req, res) => {
  db.orders = db.orders.filter(o => o.id !== req.params.id); save(); res.json({ ok: true });
});

// ---------- users CRUD (admin) ----------
app.get('/api/users', auth, adminOnly, (req, res) => res.json(db.users.map(publicUser)));
app.post('/api/users', auth, adminOnly, (req, res) => {
  const { name, username, password, role } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password are required' });
  if (db.users.some(u => u.username === username)) return res.status(400).json({ error: 'Username already taken' });
  const u = { id: crypto.randomUUID(), name, username, role: role === 'admin' ? 'admin' : 'staff', password: hash(password) };
  db.users.push(u); save(); res.status(201).json(publicUser(u));
});
app.put('/api/users/:id', auth, adminOnly, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const { name, username, password, role } = req.body;
  if (username && username !== u.username && db.users.some(x => x.username === username))
    return res.status(400).json({ error: 'Username already taken' });
  if (name) u.name = name;
  if (username) u.username = username;
  if (role) u.role = role === 'admin' ? 'admin' : 'staff';
  if (password) u.password = hash(password);
  if (!db.users.some(x => x.role === 'admin')) { u.role = 'admin'; }
  save(); res.json(publicUser(u));
});
app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "You can't delete your own account" });
  db.users = db.users.filter(u => u.id !== req.params.id); save(); res.json({ ok: true });
});

// ---------- automatic backup ----------
// Copies data.json into the "backups" folder on start and every 6 hours (one file per day, last 14 days kept)
const BK_DIR = path.join(DATA_DIR, 'backups');
function backup() {
  if (!fs.existsSync(DB_FILE)) return;
  try {
    fs.mkdirSync(BK_DIR, { recursive: true });
    fs.copyFileSync(DB_FILE, path.join(BK_DIR, 'data-' + todayStr() + '.json'));
    fs.readdirSync(BK_DIR).filter(f => /^data-.*\.json$/.test(f)).sort().slice(0, -14)
      .forEach(f => fs.unlinkSync(path.join(BK_DIR, f)));
  } catch (e) { console.log('Backup failed:', e.message); }
}
if (!USE_PG) { backup(); setInterval(backup, 6 * 60 * 60 * 1000); }

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log('Paperthreads running on port ' + PORT)))
  .catch(e => { console.error('Could not start (database problem):', e.message); process.exit(1); });
