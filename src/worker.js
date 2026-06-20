// worker.js — 富文本轻量备忘录（Cloudflare Workers + D1）
// 特性：HMAC 无状态会话 / 登录防爆破（按 IP 限流封禁）/ 富文本编辑 / HTML 消毒
// 加密：暂未启用，但接缝在服务端，密钥用 Secret（用户无需输入任何口令）。
//
// 绑定 / 机密：
//   D1 绑定名：NOTE_DB
//   Secret：AUTH_PASSWORD    登录密码
//   Secret：SESSION_SECRET   会话签名密钥（随机长串）
//   Secret：ENC_KEY          （以后启用加密时再加；现在不需要）

// ===== 可调参数 =====
const COOKIE_NAME = 'session';
const SESSION_TTL = 7 * 24 * 60 * 60;        // 会话有效期（秒）

// 登录防爆破
const LOGIN_WINDOW_MIN = 10;                 // 统计窗口（分钟）
const LOGIN_MAX_FAILS  = 5;                  // 窗口内允许的失败次数
const LOGIN_BAN_SEC    = 900;                // 触发后封禁时长（秒）

// 加密总开关：以后置 true 并配置 Secret ENC_KEY 即可，数据库无需迁移
const ENC_ENABLED = false;
// ====================

const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname, method = request.method;
    try {
      if (method === 'GET' && p === '/') return html(PAGE);
      if (p === '/api/login' && method === 'POST') return handleLogin(request, env);
      if (p === '/api/logout' && method === 'POST') return handleLogout();
      if (p.startsWith('/api/')) {
        if (!(await isAuthed(request, env))) return json({ error: 'unauthorized' }, 401);
        return handleApi(request, env, url);
      }
      return new Response('Not Found', { status: 404 });
    } catch (e) {
      return json({ error: 'internal', detail: String(e) }, 500);
    }
  },
};

// ---------- 会话鉴权（HMAC 无状态） ----------

function timingSafeEqual(a, b) {
  const ab = enc.encode(a), bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}
function b64url(bytes) {
  return btoa(String.fromCharCode.apply(null, bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(new Uint8Array(sig));
}
async function makeToken(env) {
  const payload = b64url(enc.encode(JSON.stringify({ exp: Date.now() + SESSION_TTL * 1000 })));
  return payload + '.' + (await hmac(env.SESSION_SECRET, payload));
}
async function verifyToken(env, token) {
  if (!token || token.indexOf('.') < 0) return false;
  const parts = token.split('.');
  const expected = await hmac(env.SESSION_SECRET, parts[0]);
  if (!timingSafeEqual(parts[1], expected)) return false;
  try {
    const data = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof data.exp === 'number' && data.exp > Date.now();
  } catch (e) { return false; }
}
function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function isAuthed(request, env) { return verifyToken(env, getCookie(request, COOKIE_NAME)); }

function setCookie(token, ttl) {
  return COOKIE_NAME + '=' + token + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + ttl;
}
function banned(retrySec) {
  return new Response(JSON.stringify({ error: 'too_many_attempts', retry_after: retrySec }), {
    status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(retrySec) } });
}

// ---------- 登录 + 防爆破 ----------
// 用 CF-Connecting-IP 作为限流键：它由 Cloudflare 边缘写入，客户端无法伪造。
// 切勿用 X-Forwarded-For 之类客户端可控的头来做限流，那等于没限。

async function handleLogin(request, env) {
  const db = env.NOTE_DB;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const windowMs = LOGIN_WINDOW_MIN * 60 * 1000;

  const rec = await db.prepare(
    'SELECT fails, first_fail_at, banned_until FROM login_attempts WHERE ip = ?').bind(ip).first();

  // 封禁中：直接拒绝，不读 body、不验密码、不写库（封禁期间零写入，抗刷）
  if (rec && rec.banned_until > now) return banned(Math.ceil((rec.banned_until - now) / 1000));

  const body = await request.json().catch(() => ({}));
  const pw = typeof body.password === 'string' ? body.password : '';
  const ok = !!env.AUTH_PASSWORD && timingSafeEqual(pw, env.AUTH_PASSWORD);

  if (ok) {
    if (rec) await db.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run(); // 成功即清零
    const token = await makeToken(env);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': setCookie(token, SESSION_TTL) } });
  }

  // 失败：在窗口内累加，否则重置窗口；达到阈值则封禁
  let fails = 1, firstAt = now, bannedUntil = 0;
  if (rec && (now - rec.first_fail_at) <= windowMs) { fails = rec.fails + 1; firstAt = rec.first_fail_at; }
  if (fails >= LOGIN_MAX_FAILS) { bannedUntil = now + LOGIN_BAN_SEC * 1000; fails = 0; firstAt = now; }

  await db.prepare(
    'INSERT INTO login_attempts (ip, fails, first_fail_at, banned_until) VALUES (?,?,?,?) ' +
    'ON CONFLICT(ip) DO UPDATE SET fails=excluded.fails, first_fail_at=excluded.first_fail_at, banned_until=excluded.banned_until'
  ).bind(ip, fails, firstAt, bannedUntil).run();

  if (bannedUntil) return banned(LOGIN_BAN_SEC);
  return json({ error: 'bad_password', remaining: LOGIN_MAX_FAILS - fails }, 401);
}

function handleLogout() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': setCookie('', 0) } });
}

// ---------- 服务端加密接缝（密钥来自 Secret，用户不输入任何东西） ----------
// 现在 ENC_ENABLED=false，全程明文直通，行为和不加密完全一致。
// 启用时：把 ENC_ENABLED 置 true、配置 Secret ENC_KEY，按下方注释填充 AES-GCM 即可。
// 安全边界（务必清楚）：密钥在服务端，这是"静态加密"——能防 D1 数据被单独导出/泄露，
// 防不住 Worker 或账号本身被攻破（拿到 ENC_KEY 的人能解密）。它不是端到端、不是零知识。

async function getKey(env) {
  // 由 Secret 派生 AES-256-GCM 密钥（HKDF）。仅在启用加密时调用。
  const ikm = await crypto.subtle.importKey('raw', enc.encode(env.ENC_KEY), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('notes-v1'), info: enc.encode('content') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encStore(env, text) {
  if (!ENC_ENABLED) return { data: text, format: 0 };
  const key = await getKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text || ''));
  return { data: b64url(iv) + '.' + b64url(new Uint8Array(ct)), format: 1 };
}
async function decStore(env, data, format) {
  if (!format) return data || '';                 // format=0 旧明文，直接返回
  const key = await getKey(env);
  const parts = String(data).split('.');
  const iv = Uint8Array.from(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

// ---------- 业务 API ----------

async function handleApi(request, env, url) {
  const p = url.pathname, method = request.method, db = env.NOTE_DB;

  if (p === '/api/notes') {
    if (method === 'GET') {
      const r = await db.prepare(
        'SELECT id, title, format, updated_at FROM notes ORDER BY updated_at DESC').all();
      const rows = r.results || [], out = [];
      for (const row of rows) {
        out.push({ id: row.id, title: await decStore(env, row.title, row.format), updated_at: row.updated_at });
      }
      return json(out);
    }
    if (method === 'POST') {
      const now = Date.now();
      const e = await encStore(env, '');
      const r = await db.prepare(
        'INSERT INTO notes (title, content, format, updated_at) VALUES (?,?,?,?)'
      ).bind(e.data, e.data, e.format, now).run();
      return json({ id: r.meta.last_row_id, updated_at: now });
    }
  }

  const m = p.match(/^\/api\/notes\/(\d+)$/);
  if (m) {
    const id = Number(m[1]);
    if (method === 'GET') {
      const row = await db.prepare(
        'SELECT id, title, content, format, updated_at FROM notes WHERE id = ?').bind(id).first();
      if (!row) return json({ error: 'not_found' }, 404);
      return json({
        id: row.id,
        title: await decStore(env, row.title, row.format),
        content: await decStore(env, row.content, row.format),
        updated_at: row.updated_at });
    }
    if (method === 'PUT') {
      const b = await request.json().catch(() => ({}));
      const title = typeof b.title === 'string' ? b.title.slice(0, 2000) : '';
      const content = typeof b.content === 'string' ? b.content : '';
      const et = await encStore(env, title);
      const ec = await encStore(env, content);
      const now = Date.now();
      await db.prepare(
        'UPDATE notes SET title=?, content=?, format=?, updated_at=? WHERE id=?'
      ).bind(et.data, ec.data, ec.format, now, id).run();
      return json({ ok: true, updated_at: now });
    }
    if (method === 'DELETE') {
      await db.prepare('DELETE FROM notes WHERE id = ?').bind(id).run();
      return json({ ok: true });
    }
  }
  return json({ error: 'not_found' }, 404);
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
function html(body) { return new Response(body, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); }

// ---------- 前端（无外部依赖；模板内禁用反引号与 ${}，字面换行写成 \\n） ----------

const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<title>备忘</title>
<style>
  :root{--bg:#f4f4f6;--panel:#fff;--ink:#1d1d1f;--muted:#8a8a8f;--line:#e6e6ea;--sel:#fbf2dd;--accent:#c8932f;--code-bg:#f0f0f3}
  @media (prefers-color-scheme:dark){:root{--bg:#1a1a1c;--panel:#232326;--ink:#ededef;--muted:#8d8d93;--line:#34343a;--sel:#3a3220;--accent:#e0b25a;--code-bg:#2b2b30}}
  *{box-sizing:border-box}html,body{height:100%;margin:0}
  body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;color:var(--ink);background:var(--bg);-webkit-font-smoothing:antialiased}
  button{font:inherit;cursor:pointer}
  #login{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:24px}
  #login .card{width:100%;max-width:320px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px 24px;box-shadow:0 8px 30px rgba(0,0,0,.06)}
  #login h1{margin:0 0 4px;font-size:20px;font-weight:600}
  #login p{margin:0 0 18px;color:var(--muted);font-size:13px}
  #login input{width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink);font-size:15px}
  #login input:focus{outline:none;border-color:var(--accent)}
  #login button{width:100%;margin-top:14px;padding:11px;border:none;border-radius:10px;background:var(--accent);color:#1d1d1f;font-weight:600}
  #login button:disabled{opacity:.5;cursor:not-allowed}
  #login .err{color:#d4584a;font-size:13px;min-height:18px;margin-top:10px}
  #app{display:flex;height:100vh;height:100dvh}
  .sidebar{width:300px;flex:0 0 300px;border-right:1px solid var(--line);background:var(--panel);display:flex;flex-direction:column}
  .sb-head{display:flex;align-items:center;gap:8px;padding:12px 14px;border-bottom:1px solid var(--line)}
  .sb-head .grow{flex:1;font-weight:600}
  .icon-btn{border:none;background:transparent;color:var(--muted);width:32px;height:32px;border-radius:8px;line-height:1;font-size:20px}
  .icon-btn:hover{background:var(--bg);color:var(--ink)}
  .search{margin:10px 12px;padding:8px 11px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:14px}
  .search:focus{outline:none;border-color:var(--accent)}
  .list{flex:1;overflow:auto}
  .item{padding:12px 14px;border-bottom:1px solid var(--line);cursor:pointer}
  .item:hover{background:var(--bg)}.item.active{background:var(--sel)}
  .item .t{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .item .d{font-size:12px;color:var(--muted);margin-top:3px}
  .empty-list{padding:24px 14px;color:var(--muted);font-size:13px}
  .main{flex:1;display:flex;flex-direction:column;min-width:0}
  .toolbar{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--line)}
  .toolbar .back{display:none}.toolbar .status{flex:1;color:var(--muted);font-size:13px}
  .toolbar .btn{padding:7px 14px;border:1px solid var(--line);border-radius:9px;background:var(--panel);color:var(--ink)}
  .toolbar .btn.primary{background:var(--accent);border-color:var(--accent);color:#1d1d1f;font-weight:600}
  .toolbar .btn.danger:hover{border-color:#d4584a;color:#d4584a}
  .fmtbar{display:none;flex-wrap:wrap;align-items:center;gap:6px;padding:8px 16px;border-bottom:1px solid var(--line);background:var(--panel)}
  .fmtbar.show{display:flex}
  .fmtbar select,.fmtbar input[type=color]{height:30px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--ink);padding:0 6px}
  .fmtbar input[type=color]{width:34px;padding:2px;cursor:pointer}
  .fmtbar .fb{min-width:30px;height:30px;padding:0 9px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink)}
  .fmtbar .fb:hover{background:var(--bg)}
  .fmtbar .sep{width:1px;height:20px;background:var(--line);margin:0 2px}
  .edit-wrap{flex:1;overflow:auto;padding:22px clamp(16px,5vw,48px)}
  #editor{min-height:100%;outline:none;font:16px/1.7 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;color:var(--ink)}
  #editor.is-empty:before{content:attr(data-placeholder);color:var(--muted);pointer-events:none}
  #editor img{max-width:100%;border-radius:6px}
  #editor a{color:var(--accent)}
  #editor code{background:var(--code-bg);padding:1px 5px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92em}
  #editor pre{background:var(--code-bg);padding:12px 14px;border-radius:9px;overflow:auto}
  #editor pre code{background:none;padding:0}
  @media (max-width:720px){.sidebar{flex-basis:100%;width:100%}.main{display:none}#app.viewing .sidebar{display:none}#app.viewing .main{display:flex}.toolbar .back{display:inline-block}}
</style>
</head>
<body>
  <div id="login">
    <div class="card">
      <h1>备忘</h1>
      <p>输入密码以解锁</p>
      <input id="pw" type="password" autocomplete="current-password" placeholder="密码">
      <button id="loginBtn">解锁</button>
      <div class="err" id="loginErr"></div>
    </div>
  </div>

  <div id="app" hidden>
    <aside class="sidebar">
      <div class="sb-head">
        <span class="grow">备忘</span>
        <button class="icon-btn" id="newBtn" title="新建">+</button>
        <button class="icon-btn" id="logoutBtn" title="退出" style="font-size:15px">退出</button>
      </div>
      <input class="search" id="search" placeholder="搜索标题…">
      <div class="list" id="list"></div>
    </aside>
    <section class="main">
      <div class="toolbar">
        <button class="btn back" id="backBtn">返回</button>
        <span class="status" id="status"></span>
        <button class="btn danger" id="delBtn">删除</button>
        <button class="btn primary" id="saveBtn">保存</button>
      </div>
      <div class="fmtbar" id="fmtbar">
        <select id="fFont" title="字体">
          <option value="">默认</option>
          <option value="-apple-system,Segoe UI,sans-serif">无衬线</option>
          <option value="Georgia,Times New Roman,serif">衬线</option>
          <option value="ui-monospace,Consolas,monospace">等宽</option>
          <option value="KaiTi,STKaiti,serif">楷体</option>
          <option value="SimSun,serif">宋体</option>
        </select>
        <select id="fSize" title="字号">
          <option value="">字号</option>
          <option value="12px">12</option><option value="14px">14</option>
          <option value="16px">16</option><option value="18px">18</option>
          <option value="20px">20</option><option value="24px">24</option>
          <option value="32px">32</option>
        </select>
        <input type="color" id="fColor" title="文字颜色" value="#1d1d1f">
        <span class="sep"></span>
        <button class="fb" data-cmd="bold" title="加粗"><b>B</b></button>
        <button class="fb" data-cmd="italic" title="斜体"><i>I</i></button>
        <button class="fb" data-cmd="underline" title="下划线"><u>U</u></button>
        <span class="sep"></span>
        <button class="fb" id="bCode" title="行内代码">&lt;/&gt;</button>
        <button class="fb" id="bPre" title="代码块">[ ]</button>
        <span class="sep"></span>
        <button class="fb" id="bLink" title="超链接">链接</button>
        <button class="fb" id="bImg" title="图片链接">图片</button>
        <span class="sep"></span>
        <button class="fb" id="bClear" title="清除格式">清除</button>
      </div>
      <div class="edit-wrap">
        <div id="editor" contenteditable="true" spellcheck="false" data-placeholder="开始输入…"></div>
      </div>
    </section>
  </div>

<script>
(function(){
  var notes = [], currentId = null, dirty = false, query = '', savedRange = null;
  var editor = document.getElementById('editor');
  var $ = function(id){ return document.getElementById(id); };

  // IndexedDB cache
  var dbCache = null;
  function openCache(cb){
    if (dbCache) return cb(dbCache);
    var req = indexedDB.open('cloud-note-cache', 1);
    req.onupgradeneeded = function(e){
      var idb = e.target.result;
      if (!idb.objectStoreNames.contains('notes')) idb.createObjectStore('notes', { keyPath: 'id' });
    };
    req.onsuccess = function(e){ dbCache = e.target.result; cb(dbCache); };
    req.onerror = function(){ cb(null); };
  }
  function cacheNotes(list, cb){
    openCache(function(idb){
      if (!idb) return cb && cb();
      var tx = idb.transaction('notes', 'readwrite');
      var store = tx.objectStore('notes');
      store.clear();
      list.forEach(function(n){ store.put(n); });
      tx.oncomplete = function(){ cb && cb(); };
    });
  }
  function loadCachedNotes(cb){
    openCache(function(idb){
      if (!idb) return cb([]);
      var tx = idb.transaction('notes', 'readonly');
      var req = tx.objectStore('notes').getAll();
      req.onsuccess = function(){ cb(req.result || []); };
      req.onerror = function(){ cb([]); };
    });
  }

  function api(path, opts){
    opts = opts || {}; opts.credentials = 'same-origin';
    opts.headers = Object.assign({ 'Content-Type':'application/json' }, opts.headers || {});
    return fetch(path, opts).then(function(res){
      if (res.status === 401){ showLogin(); throw new Error('unauthorized'); }
      return res.json();
    });
  }

  // ---- HTML 消毒（防存储型 XSS） ----
  var ALLOWED = {A:1,B:1,STRONG:1,I:1,EM:1,U:1,S:1,STRIKE:1,CODE:1,PRE:1,SPAN:1,DIV:1,P:1,BR:1,
    UL:1,OL:1,LI:1,H1:1,H2:1,H3:1,BLOCKQUOTE:1,IMG:1,FONT:1};
  var STYLE_PROPS = {'color':1,'background-color':1,'font-family':1,'font-size':1,
    'font-weight':1,'font-style':1,'text-decoration':1};
  function safeUrl(u){ return /^(https?:|mailto:)/i.test(String(u||'').trim()); }
  function cleanStyle(s){
    var out=[];
    String(s||'').split(';').forEach(function(d){
      var i=d.indexOf(':'); if(i<0) return;
      var prop=d.slice(0,i).trim().toLowerCase(), val=d.slice(i+1).trim();
      if (/url\\(|expression|javascript:/i.test(val)) return;
      if (STYLE_PROPS[prop]) out.push(prop+': '+val);
    });
    return out.join('; ');
  }
  function cleanNode(node){
    Array.prototype.slice.call(node.childNodes).forEach(function(c){
      if (c.nodeType === 8){ node.removeChild(c); return; }
      if (c.nodeType !== 1) return;
      var tag=c.tagName;
      if (!ALLOWED[tag]){ node.replaceChild(document.createTextNode(c.textContent||''), c); return; }
      Array.prototype.slice.call(c.attributes).forEach(function(a){
        var name=a.name.toLowerCase();
        if (name==='style'){ var v=cleanStyle(a.value); if(v) c.setAttribute('style',v); else c.removeAttribute('style'); return; }
        if (name==='href' && tag==='A'){ if(!safeUrl(a.value)) c.removeAttribute('href'); return; }
        if (name==='src' && tag==='IMG'){ if(!safeUrl(a.value)){ c.parentNode.removeChild(c); } return; }
        if (tag==='A' && (name==='target'||name==='rel')) return;
        if (tag==='FONT' && (name==='size'||name==='color'||name==='face')) return;
        c.removeAttribute(a.name);
      });
      if (c.parentNode) cleanNode(c);
      if (c.parentNode && tag==='A'){ c.setAttribute('target','_blank'); c.setAttribute('rel','noopener noreferrer'); }
    });
  }
  function sanitize(htmlStr){
    var doc=new DOMParser().parseFromString('<body>'+(htmlStr||'')+'</body>','text/html');
    cleanNode(doc.body); return doc.body.innerHTML;
  }
  function escapeHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function escapeAttr(s){ return escapeHtml(s).replace(/"/g,'&quot;'); }

  function deriveTitle(){
    var lines=(editor.innerText||'').split('\\n');
    for (var i=0;i<lines.length;i++){ var t=lines[i].trim(); if(t) return t.slice(0,80); }
    return '新建备忘';
  }
  function fmt(ts){
    var d=new Date(ts), now=new Date();
    if (d.toDateString()===now.toDateString()) return d.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
    return d.toLocaleDateString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit'});
  }
  function refreshPlaceholder(){
    var empty=(editor.innerText||'').trim()===''&&editor.querySelectorAll('img').length===0;
    editor.classList.toggle('is-empty', empty);
  }
  function showLogin(){ $('login').style.display='flex'; $('app').hidden=true; setTimeout(function(){$('pw').focus();},0); }
  function showApp(){ $('login').style.display='none'; $('app').hidden=false; }
  function setStatus(s){ $('status').textContent=s||''; }
  function showFmt(on){ $('fmtbar').classList.toggle('show', !!on); }

  function loadNotes(){
    loadCachedNotes(function(cached){
      if (cached && cached.length){
        notes=cached; showApp(); renderList();
      }
    });
    api('/api/notes').then(function(data){
      notes=(data||[]).map(function(n){ n.titlePlain=n.title||''; return n; });
      showApp(); renderList();
      cacheNotes(notes);
    }).catch(function(){});
  }
  function renderList(){
    var list=$('list'); list.innerHTML='';
    var q=query.trim().toLowerCase();
    var shown=notes.filter(function(n){ return !q||(n.titlePlain||'').toLowerCase().indexOf(q)>=0; });
    if (!shown.length){
      var e=document.createElement('div'); e.className='empty-list';
      e.textContent=q?'没有匹配的备忘':'还没有备忘，点右上角 + 新建';
      list.appendChild(e); return;
    }
    shown.forEach(function(n){
      var item=document.createElement('div'); item.className='item'+(n.id===currentId?' active':'');
      var t=document.createElement('div'); t.className='t'; t.textContent=(n.titlePlain&&n.titlePlain.trim())?n.titlePlain:'新建备忘';
      var d=document.createElement('div'); d.className='d'; d.textContent=fmt(n.updated_at);
      item.appendChild(t); item.appendChild(d);
      item.onclick=function(){ openNote(n.id); };
      list.appendChild(item);
    });
  }

  function openNote(id){
    function load(){
      api('/api/notes/'+id).then(function(note){
        currentId=id; dirty=false;
        editor.innerHTML=sanitize(note.content); refreshPlaceholder();
        setStatus('编辑于 '+fmt(note.updated_at)); renderList(); showFmt(true);
        $('app').classList.add('viewing'); editor.focus();
      });
    }
    if (dirty) saveNote(load); else load();
  }
  function newNote(){
    function go(){
      api('/api/notes',{method:'POST'}).then(function(n){
        notes.unshift({ id:n.id, title:'', updated_at:n.updated_at, titlePlain:'新建备忘' });
        currentId=n.id; dirty=false; editor.innerHTML=''; refreshPlaceholder();
        setStatus('新建'); renderList(); showFmt(true);
        $('app').classList.add('viewing'); editor.focus();
      });
    }
    if (dirty) saveNote(go); else go();
  }
  function saveNote(after){
    if (currentId===null) return;
    var content=sanitize(editor.innerHTML), titleText=deriveTitle();
    setStatus('保存中…');
    api('/api/notes/'+currentId,{ method:'PUT', body: JSON.stringify({ title:titleText, content:content }) })
      .then(function(r){
        dirty=false;
        var n=notes.find(function(x){return x.id===currentId;});
        if(n){ n.titlePlain=titleText; n.updated_at=r.updated_at; }
        notes.sort(function(a,b){return b.updated_at-a.updated_at;});
        renderList(); setStatus('已保存 '+fmt(r.updated_at));
        cacheNotes(notes);
        if (typeof after==='function') after();
      });
  }
  function deleteNote(){
    if (currentId===null) return;
    if (!confirm('删除这条备忘？')) return;
    var id=currentId;
    api('/api/notes/'+id,{method:'DELETE'}).then(function(){
      notes=notes.filter(function(x){return x.id!==id;});
      currentId=null; dirty=false; editor.innerHTML=''; refreshPlaceholder();
      setStatus(''); renderList(); showFmt(false); $('app').classList.remove('viewing');
      cacheNotes(notes);
    });
  }

  // ---- 富文本（contenteditable + execCommand） ----
  function saveSel(){ var s=window.getSelection(); if (s.rangeCount && editor.contains(s.anchorNode)) savedRange=s.getRangeAt(0).cloneRange(); }
  function withSel(fn){
    editor.focus();
    if (savedRange){ var s=window.getSelection(); s.removeAllRanges(); s.addRange(savedRange); }
    fn(); saveSel(); dirty=true; setStatus('未保存'); refreshPlaceholder();
  }
  function exec(cmd,val){ document.execCommand('styleWithCSS',false,true); document.execCommand(cmd,false,val); }
  document.addEventListener('selectionchange', saveSel);

  Array.prototype.forEach.call(document.querySelectorAll('.fmtbar .fb'), function(b){
    b.addEventListener('mousedown', function(e){ e.preventDefault(); });
  });
  Array.prototype.forEach.call(document.querySelectorAll('.fmtbar [data-cmd]'), function(b){
    b.addEventListener('click', function(){ withSel(function(){ exec(b.getAttribute('data-cmd')); }); });
  });
  $('fFont').addEventListener('change', function(e){ var v=e.target.value; withSel(function(){ if(v) exec('fontName',v); }); e.target.selectedIndex=0; });
  $('fColor').addEventListener('input', function(e){ var v=e.target.value; withSel(function(){ exec('foreColor',v); }); });
  $('fSize').addEventListener('change', function(e){
    var px=e.target.value; e.target.selectedIndex=0; if(!px) return;
    withSel(function(){
      document.execCommand('fontSize',false,'7');
      var marks=editor.querySelectorAll('font[size="7"]');
      for (var i=0;i<marks.length;i++){ marks[i].removeAttribute('size'); marks[i].style.fontSize=px; }
    });
  });
  $('bCode').addEventListener('click', function(){ withSel(function(){
    var t=window.getSelection().toString();
    if (t) document.execCommand('insertHTML',false,'<code>'+escapeHtml(t)+'</code>');
  }); });
  $('bPre').addEventListener('click', function(){ withSel(function(){
    var t=window.getSelection().toString();
    document.execCommand('insertHTML',false,'<pre><code>'+escapeHtml(t||'')+'</code></pre><p><br></p>');
  }); });
  $('bLink').addEventListener('click', function(){
    var url=prompt('链接地址（http/https）'); if(!url) return;
    if(!/^https?:\\/\\//i.test(url)) url='https://'+url;
    withSel(function(){
      var sel=window.getSelection();
      if (sel && sel.toString()) document.execCommand('createLink',false,url);
      else document.execCommand('insertHTML',false,'<a href="'+escapeAttr(url)+'" target="_blank" rel="noopener noreferrer">'+escapeHtml(url)+'</a>');
    });
  });
  $('bImg').addEventListener('click', function(){
    var url=prompt('图片地址（http/https，仅插入链接，不上传）'); if(!url) return;
    if(!/^https?:\\/\\//i.test(url)){ alert('仅支持 http/https 链接'); return; }
    withSel(function(){ document.execCommand('insertImage',false,url); });
  });
  $('bClear').addEventListener('click', function(){ withSel(function(){ document.execCommand('removeFormat'); document.execCommand('unlink'); }); });

  editor.addEventListener('paste', function(e){
    e.preventDefault();
    var cd=e.clipboardData||window.clipboardData;
    var htmlStr=cd.getData('text/html');
    var clean=htmlStr?sanitize(htmlStr):escapeHtml(cd.getData('text/plain')).replace(/\\n/g,'<br>');
    document.execCommand('insertHTML',false,clean);
    dirty=true; setStatus('未保存'); refreshPlaceholder();
  });
  editor.addEventListener('input', function(){ dirty=true; setStatus('未保存'); refreshPlaceholder(); });

  $('saveBtn').onclick=function(){ saveNote(); };
  $('delBtn').onclick=deleteNote;
  $('newBtn').onclick=newNote;
  $('backBtn').onclick=function(){ if(dirty) saveNote(); $('app').classList.remove('viewing'); };
  $('logoutBtn').onclick=function(){ if(confirm('确定要退出登录吗？')) api('/api/logout',{method:'POST'}).then(function(){ location.reload(); }); };
  $('search').addEventListener('input', function(e){ query=e.target.value; renderList(); });
  document.addEventListener('keydown', function(e){
    if ((e.metaKey||e.ctrlKey) && e.key.toLowerCase()==='s'){ e.preventDefault(); saveNote(); }
  });
  window.addEventListener('beforeunload', function(e){ if(dirty){ e.preventDefault(); e.returnValue=''; } });

  function doLogin(){
    $('loginErr').textContent=''; $('loginBtn').disabled=true;
    fetch('/api/login',{ method:'POST', credentials:'same-origin',
      headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ password:$('pw').value }) })
      .then(function(res){
        if (res.ok){ $('pw').value=''; $('loginBtn').disabled=false; loadNotes(); return; }
        return res.json().then(function(d){
          $('loginBtn').disabled=false;
          if (res.status===429) $('loginErr').textContent='尝试过多，请约 '+(d.retry_after||60)+' 秒后再试';
          else if (typeof d.remaining==='number') $('loginErr').textContent='密码错误，还可尝试 '+d.remaining+' 次';
          else $('loginErr').textContent='密码错误';
        });
      })
      .catch(function(){ $('loginBtn').disabled=false; $('loginErr').textContent='网络错误'; });
  }
  $('loginBtn').onclick=doLogin;
  $('pw').addEventListener('keydown', function(e){ if(e.key==='Enter') doLogin(); });

  loadNotes();
})();
</script>
</body>
</html>`;
