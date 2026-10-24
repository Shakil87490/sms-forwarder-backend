/* SMS Forwarder — multi-user live backend (single file) */
try { require('dotenv').config(); } catch (e) { /* dotenv optional */ }

const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.db');

// ---------- DB ----------
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
  name TEXT NOT NULL, api_key TEXT UNIQUE NOT NULL, last_seen INTEGER, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, device_id INTEGER NOT NULL,
  source TEXT, sender TEXT, body TEXT, sim TEXT, received_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_msg_user ON messages(user_id, received_at DESC);
`);

// ---------- auth helpers ----------
const sign = (u) => jwt.sign({ id: u.id, email: u.email }, SECRET, { expiresIn: '30d' });
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

// ---------- app ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

// auth
app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6)
    return res.status(400).json({ error: 'Email and password (min 6 chars) required' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase()))
    return res.status(409).json({ error: 'Email already registered' });
  const info = db.prepare('INSERT INTO users (email,password,created_at) VALUES (?,?,?)')
    .run(email.toLowerCase(), bcrypt.hashSync(password, 10), Date.now());
  const user = { id: info.lastInsertRowid, email: email.toLowerCase() };
  res.json({ token: sign(user), user });
});
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(password || '', u.password))
    return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: sign(u), user: { id: u.id, email: u.email } });
});

// devices
app.get('/api/devices', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT id,name,api_key,last_seen,created_at FROM devices WHERE user_id=? ORDER BY id').all(req.user.id));
});
app.post('/api/devices', requireAuth, (req, res) => {
  const name = (req.body && req.body.name) || 'My Phone';
  const key = crypto.randomBytes(24).toString('hex');
  const info = db.prepare('INSERT INTO devices (user_id,name,api_key,created_at) VALUES (?,?,?,?)')
    .run(req.user.id, name, key, Date.now());
  res.json({ id: info.lastInsertRowid, name, api_key: key });
});
app.delete('/api/devices/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM devices WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ingest (phone)
app.post('/api/ingest', (req, res) => {
  const key = req.headers['x-api-key'] || (req.body && req.body.api_key) || req.query.api_key;
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  const dev = db.prepare('SELECT * FROM devices WHERE api_key=?').get(key);
  if (!dev) return res.status(401).json({ error: 'Invalid API key' });
  const b = req.body || {};
  const m = {
    user_id: dev.user_id, device_id: dev.id, source: b.source || 'SMS',
    sender: b.sender || 'Unknown', body: b.message || b.body || '', sim: b.sim || '', received_at: Date.now()
  };
  const info = db.prepare('INSERT INTO messages (user_id,device_id,source,sender,body,sim,received_at) VALUES (?,?,?,?,?,?,?)')
    .run(m.user_id, m.device_id, m.source, m.sender, m.body, m.sim, m.received_at);
  db.prepare('UPDATE devices SET last_seen=? WHERE id=?').run(Date.now(), dev.id);
  io.to('user:' + dev.user_id).emit('message', Object.assign({ id: info.lastInsertRowid, device: dev.name }, m));
  res.json({ ok: true, id: info.lastInsertRowid });
});

// messages
app.get('/api/messages', requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const offset = parseInt(req.query.offset) || 0;
  const q = (req.query.q || '').trim();
  let rows;
  if (q) {
    const like = '%' + q + '%';
    rows = db.prepare(`SELECT m.*, d.name AS device FROM messages m JOIN devices d ON d.id=m.device_id
      WHERE m.user_id=? AND (m.sender LIKE ? OR m.body LIKE ?) ORDER BY m.received_at DESC LIMIT ? OFFSET ?`)
      .all(req.user.id, like, like, limit, offset);
  } else {
    rows = db.prepare(`SELECT m.*, d.name AS device FROM messages m JOIN devices d ON d.id=m.device_id
      WHERE m.user_id=? ORDER BY m.received_at DESC LIMIT ? OFFSET ?`).all(req.user.id, limit, offset);
  }
  res.json(rows);
});
app.delete('/api/messages/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM messages WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ---------- socket.io live ----------
io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth && socket.handshake.auth.token, SECRET); next(); }
  catch (e) { next(new Error('unauthorized')); }
});
io.on('connection', (socket) => socket.join('user:' + socket.user.id));

server.listen(PORT, () => console.log('SMS Forwarder backend on http://localhost:' + PORT));
