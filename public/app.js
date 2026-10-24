const $ = (id) => document.getElementById(id);
let token = localStorage.getItem('token') || null;
let socket = null;
let convs = new Map();        // sender -> {sender, source, messages:[], lastTime, lastBody}
let activeSender = null;

const api = async (path, opts = {}) => {
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  const r = await fetch('/api' + path, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
};

/* ---------- Auth ---------- */
async function doAuth(kind) {
  $('authErr').textContent = '';
  try {
    const res = await api('/auth/' + kind, {
      method: 'POST',
      body: JSON.stringify({ email: $('email').value.trim(), password: $('password').value })
    });
    token = res.token;
    localStorage.setItem('token', token);
    localStorage.setItem('email', res.user.email);
    showApp();
  } catch (e) { $('authErr').textContent = e.message; }
}
$('btnLogin').onclick = () => doAuth('login');
$('btnRegister').onclick = () => doAuth('register');
$('btnLogout').onclick = () => {
  localStorage.removeItem('token'); token = null;
  if (socket) socket.disconnect();
  $('app').classList.add('hidden'); $('auth').classList.remove('hidden');
};

/* ---------- App ---------- */
async function showApp() {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  await loadMessages();
  connectSocket();
}

function connectSocket() {
  socket = io({ auth: { token } });
  socket.on('message', (m) => addMessage(m, true));
}

async function loadMessages() {
  convs = new Map();
  const list = await api('/messages?limit=500');   // newest first
  list.reverse().forEach((m) => addMessage(m, false)); // insert oldest→newest
  renderConvList();
  if (!convs.size) { $('convEmpty').classList.remove('hidden'); }
  else { $('convEmpty').classList.add('hidden'); }
}

/* add one message to its conversation */
function addMessage(m, live) {
  const key = m.sender || 'Unknown';
  let c = convs.get(key);
  if (!c) { c = { sender: key, source: m.source, messages: [], lastTime: 0, lastBody: '' }; convs.set(key, c); }
  c.messages.push(m);
  c.lastTime = m.received_at;
  c.lastBody = m.body;
  c.source = m.source;
  if (live) {
    $('convEmpty').classList.add('hidden');
    renderConvList();
    if (activeSender === key) { appendBubble(m); scrollBubbles(); }
  }
}

/* ---------- Conversation list ---------- */
function renderConvList() {
  const q = $('search').value.trim().toLowerCase();
  const arr = [...convs.values()].sort((a, b) => b.lastTime - a.lastTime)
    .filter(c => !q || c.sender.toLowerCase().includes(q) || c.lastBody.toLowerCase().includes(q));
  $('convList').innerHTML = arr.map(c => `
    <button class="conv ${c.sender === activeSender ? 'active' : ''}" onclick="openConv('${esc(c.sender).replace(/'/g, "\\'")}')">
      <div class="avatar" style="background:${color(c.sender)}">${initial(c.sender)}</div>
      <div class="conv-main">
        <div class="conv-top">
          <span class="conv-name">${esc(c.sender)}</span>
          <span class="conv-time">${fmtShort(c.lastTime)}</span>
        </div>
        <div class="conv-prev">${esc(c.lastBody)}</div>
      </div>
    </button>`).join('');
}
$('search').oninput = renderConvList;

window.openConv = (sender) => {
  activeSender = sender;
  const c = convs.get(sender);
  if (!c) return;
  $('threadEmpty').classList.add('hidden');
  $('threadView').classList.remove('hidden');
  $('threadName').textContent = sender;
  $('threadSub').textContent = c.messages.length + ' message' + (c.messages.length > 1 ? 's' : '');
  const av = $('threadAvatar');
  av.textContent = initial(sender); av.style.background = color(sender);
  $('bubbles').innerHTML = '';
  c.messages.forEach(appendBubble);
  scrollBubbles();
  renderConvList();
  $('app').classList.add('thread-open');
};
$('btnBack').onclick = () => { $('app').classList.remove('thread-open'); activeSender = null; renderConvList(); };

function appendBubble(m) {
  const isApp = m.source && m.source !== 'SMS';
  const el = document.createElement('div');
  el.className = 'b-row';
  el.innerHTML = `<div class="bubble">${esc(m.body || '')}</div>
    <div class="b-time">${fmtFull(m.received_at)}${isApp ? '<span class="b-src app">' + esc(m.source) + '</span>' : ''}${m.sim ? ' · ' + esc(m.sim) : ''}</div>`;
  $('bubbles').appendChild(el);
}
function scrollBubbles() { const b = $('bubbles'); b.scrollTop = b.scrollHeight; }

/* ---------- Devices modal ---------- */
$('btnDevices').onclick = () => { $('devModal').classList.remove('hidden'); loadDevices(); };
$('devClose').onclick = () => $('devModal').classList.add('hidden');
$('btnAddDevice').onclick = async () => {
  const name = prompt('Device name?', 'My Phone');
  if (name === null) return;
  await api('/devices', { method: 'POST', body: JSON.stringify({ name }) });
  loadDevices();
};
async function loadDevices() {
  const list = await api('/devices');
  const origin = location.origin;
  $('devList').innerHTML = list.map(d => {
    const url = origin + '/api/ingest?api_key=' + d.api_key;
    return `<div class="dev">
      <b>${esc(d.name)}</b> <span class="small muted">${d.last_seen ? '· active' : '· never used'}</span>
      <div class="url">${url}</div>
      <div class="acts">
        <button class="chip" onclick="copyTxt('${url}')">Copy ingest URL</button>
        <button class="chip danger" onclick="delDev(${d.id})">Delete</button>
      </div>
    </div>`;
  }).join('') || '<p class="small muted">No devices yet.</p>';
}
window.delDev = async (id) => { if (confirm('Delete this device?')) { await api('/devices/' + id, { method: 'DELETE' }); loadDevices(); } };
window.copyTxt = (t) => { navigator.clipboard.writeText(t); alert('Copied the ingest URL — paste it into the phone app Webhook field.'); };

/* ---------- utils ---------- */
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function initial(s) { const t = String(s).trim(); return t ? t[0].toUpperCase() : '#'; }
function color(s) {
  const palette = ['#1a73e8', '#d93025', '#188038', '#e37400', '#9334e6', '#1e8e3e', '#c5221f', '#a142f4'];
  let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}
function fmtFull(ts) { return new Date(ts).toLocaleString(); }
function fmtShort(ts) {
  const d = new Date(ts), now = new Date();
  if (d.toDateString() === now.toDateString())
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

if (token) showApp();
