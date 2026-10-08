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

let db = { users: [], orders: [], seq: 0 };
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
if (!db.users.length) {
  db.users.push({ id: crypto.randomUUID(), name: 'Admin', username: 'admin', role: 'admin', password: hash('admin123') });
  console.log('First run: login with admin / admin123 (change it in Users page)');
}
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
save();

// ---------- auth ----------
const sessions = new Map();
const publicUser = ({ password, ...u }) => u;
const auth = (req, res, next) => {
  const u = sessions.get((req.headers.authorization || '').replace('Bearer ', ''));
  if (!u) return res.status(401).json({ error: 'Please log in' });
  req.user = db.users.find(x => x.id === u);
  if (!req.user) return res.status(401).json({ error: 'Please log in' });
  next();
};
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.users.find(x => x.username === username);
  if (!u || !verify(password || '', u.password)) return res.status(400).json({ error: 'Wrong username or password' });
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, u.id);
  res.json({ token, user: publicUser(u) });
});
app.post('/api/logout', auth, (req, res) => {
  sessions.delete((req.headers.authorization || '').replace('Bearer ', ''));
  res.json({ ok: true });
});
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
  // an order can only be completed after full payment is received
  if (req.body.status === 'Completed' && was.status !== 'Completed' && was.status !== 'Delivered' && o.remaining > 0)
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
    o.courierStatus = req.body.courierStatus;
    o.status = o.courierStatus === 'Delivered' ? 'Delivered' : 'Completed';
    syncCourier(o);
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
  try {
    fs.mkdirSync(BK_DIR, { recursive: true });
    fs.copyFileSync(DB_FILE, path.join(BK_DIR, 'data-' + todayStr() + '.json'));
    fs.readdirSync(BK_DIR).filter(f => /^data-.*\.json$/.test(f)).sort().slice(0, -14)
      .forEach(f => fs.unlinkSync(path.join(BK_DIR, f)));
  } catch (e) { console.log('Backup failed:', e.message); }
}
backup();
setInterval(backup, 6 * 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Paperthreads running at http://localhost:' + PORT));
