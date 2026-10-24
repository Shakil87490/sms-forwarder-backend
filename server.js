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

app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));
app.get('/', (req, res) => { res.type('html').send(DASHBOARD); });

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

// ---------- dashboard (inline, no template-literals inside) ----------
const DASHBOARD = [
'<!doctype html><html lang="en"><head><meta charset="utf-8"/>',
'<meta name="viewport" content="width=device-width, initial-scale=1"/>',
'<title>SMS Forwarder - Live Dashboard</title><style>',
':root{--pri:#2563EB;--pri2:#7C3AED;--bg:#0f172a;--card:#1e293b;--card2:#273449;--text:#e2e8f0;--muted:#94a3b8;--line:#334155;--accent:#10b981;--err:#f87171}',
'*{box-sizing:border-box}body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}',
'.hidden{display:none!important}.muted{color:var(--muted)}.small{font-size:12px}.err{color:var(--err);min-height:18px;font-size:13px}',
'.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:linear-gradient(135deg,var(--pri),var(--pri2))}',
'.auth-card{width:100%;max-width:380px;text-align:center}.auth-card h1{margin:0 0 2px}.auth-card input{margin-top:12px}',
'.row{display:flex;gap:10px;margin-top:14px}.row button{flex:1}',
'.topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:linear-gradient(135deg,var(--pri),var(--pri2));position:sticky;top:0;z-index:5}',
'.brand{font-weight:700;font-size:18px}.right{display:flex;align-items:center;gap:12px}',
'.pill{font-size:11px;background:rgba(255,255,255,.2);padding:2px 8px;border-radius:999px;color:#d1fae5}',
'.wrap{max-width:860px;margin:0 auto;padding:18px;display:grid;gap:18px}',
'.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}',
'.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.card-head h2{margin:0;font-size:17px}',
'input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card2);color:var(--text);font-size:14px}',
'input:focus{outline:none;border-color:var(--pri)}#search{max-width:260px}',
'button{cursor:pointer;border:none;border-radius:10px;padding:10px 14px;font-size:14px;font-weight:600}',
'button.primary{background:var(--pri);color:#fff}button.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}',
'button.sm{padding:7px 12px;font-size:13px}button.danger{background:transparent;color:var(--err);border:1px solid var(--err)}',
'.device{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px;border:1px solid var(--line);border-radius:12px;margin-bottom:10px;background:var(--card2)}',
'.device .k{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--accent);word-break:break-all}.device .meta{font-size:12px;color:var(--muted)}',
'.copy{font-size:12px;background:var(--line);padding:4px 8px;border-radius:8px}',
'.feed{display:flex;flex-direction:column;gap:10px;max-height:60vh;overflow:auto}',
'.msg{padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--card2)}',
'.msg .top{display:flex;justify-content:space-between;gap:10px;font-size:13px}.msg .sender{font-weight:700}',
'.msg .src{font-size:11px;background:var(--pri);color:#fff;padding:1px 7px;border-radius:999px}.msg .src.app{background:var(--accent)}',
'.msg .body{margin-top:6px;white-space:pre-wrap;font-size:14px}.msg .time{color:var(--muted);font-size:11px;margin-top:6px}',
'</style></head><body>',
'<div id="auth" class="auth"><div class="card auth-card"><h1>SMS Forwarder</h1><p class="muted">Live multi-user dashboard</p>',
'<input id="email" type="email" placeholder="Email"/><input id="password" type="password" placeholder="Password (min 6)"/>',
'<div class="row"><button id="btnLogin" class="primary">Login</button><button id="btnRegister" class="ghost">Register</button></div>',
'<p id="authErr" class="err"></p></div></div>',
'<div id="app" class="hidden"><header class="topbar"><div class="brand">SMS Forwarder <span class="pill" id="livePill">live</span></div>',
'<div class="right"><span id="whoami" class="muted"></span><button id="btnLogout" class="ghost sm">Logout</button></div></header>',
'<main class="wrap"><section class="card"><div class="card-head"><h2>Devices</h2><button id="btnAddDevice" class="primary sm">+ Add device</button></div>',
'<div id="devices"></div><p class="muted small">Add a device to get an API key + ingest URL for the phone app.</p></section>',
'<section class="card"><div class="card-head"><h2>Messages</h2><input id="search" placeholder="Search sender / text..."/></div>',
'<div id="messages" class="feed"></div></section></main></div>',
'<script src="/socket.io/socket.io.js"></script><script>',
"var $=function(id){return document.getElementById(id)};var token=localStorage.getItem('token')||null;var socket=null;",
"function api(p,o){o=o||{};o.headers=Object.assign({'Content-Type':'application/json'},o.headers||{});if(token)o.headers['Authorization']='Bearer '+token;",
"return fetch('/api'+p,o).then(function(r){return r.json().catch(function(){return{}}).then(function(d){if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d})})}",
"function doAuth(k){$('authErr').textContent='';var email=$('email').value.trim();var password=$('password').value;",
"api('/auth/'+k,{method:'POST',body:JSON.stringify({email:email,password:password})}).then(function(res){token=res.token;localStorage.setItem('token',token);localStorage.setItem('email',res.user.email);showApp()}).catch(function(e){$('authErr').textContent=e.message})}",
"$('btnLogin').onclick=function(){doAuth('login')};$('btnRegister').onclick=function(){doAuth('register')};",
"$('btnLogout').onclick=function(){localStorage.removeItem('token');token=null;if(socket)socket.disconnect();$('app').classList.add('hidden');$('auth').classList.remove('hidden')};",
"function showApp(){$('auth').classList.add('hidden');$('app').classList.remove('hidden');$('whoami').textContent=localStorage.getItem('email')||'';loadDevices();loadMessages();connectSocket()}",
"function connectSocket(){socket=io({auth:{token:token}});socket.on('connect',function(){$('livePill').style.opacity=1});socket.on('disconnect',function(){$('livePill').style.opacity=.4});socket.on('message',function(m){prependMessage(m,true)})}",
"function loadDevices(){api('/devices').then(function(list){var o=location.origin;$('devices').innerHTML=list.map(function(d){return '<div class=device><div><div><b>'+esc(d.name)+'</b></div><div class=k>key: '+d.api_key+'</div><div class=meta>URL: '+o+'/api/ingest '+(d.last_seen?'- last seen '+fmt(d.last_seen):'- never used')+'</div></div><div style=\"display:flex;gap:6px;flex-direction:column\"><button class=copy onclick=\"copyKey(\\''+d.api_key+'\\')\">Copy key</button><button class=\"danger sm\" onclick=\"delDevice('+d.id+')\">Delete</button></div></div>'}).join('')||'<p class=\"muted small\">No devices yet.</p>'})}",
"$('btnAddDevice').onclick=function(){var name=prompt('Device name?','My Phone');if(name===null)return;api('/devices',{method:'POST',body:JSON.stringify({name:name})}).then(loadDevices)};",
"window.delDevice=function(id){if(confirm('Delete this device?'))api('/devices/'+id,{method:'DELETE'}).then(loadDevices)};",
"window.copyKey=function(k){navigator.clipboard.writeText(k);alert('API key copied')};",
"function loadMessages(){var q=$('search').value.trim();api('/messages?limit=200'+(q?'&q='+encodeURIComponent(q):'')).then(function(list){$('messages').innerHTML='';list.forEach(function(m){prependMessage(m,false,true)})})}",
"var st;$('search').oninput=function(){clearTimeout(st);st=setTimeout(loadMessages,300)};",
"function prependMessage(m,animate,append){var el=document.createElement('div');el.className='msg';var isApp=(m.source&&m.source!=='SMS');",
"el.innerHTML='<div class=top><span class=sender>'+esc(m.sender||'Unknown')+'</span><span class=\"src '+(isApp?'app':'')+'\">'+esc(m.source||'SMS')+'</span></div><div class=body>'+esc(m.body||'')+'</div><div class=time>'+esc(m.device||'')+' - '+fmt(m.received_at)+(m.sim?' - '+esc(m.sim):'')+'</div>';",
"var box=$('messages');if(append)box.appendChild(el);else box.insertBefore(el,box.firstChild)}",
"function esc(s){return String(s).replace(/[&<>\"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]})}",
"function fmt(ts){return new Date(ts).toLocaleString()}",
"if(token)showApp();",
'</script></body></html>'
].join('\n');
