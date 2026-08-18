#!/usr/bin/env node
/**
 * VeryKey WebUI — TOTP 认证 + 密钥管理（零依赖单文件）
 * 监听 127.0.0.1:3081，外部访问走 SSH 隧道
 */
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const V = require('./vault.js');

const PORT = parseInt(process.env.VERYKEY_PORT || '3081', 10);
const HOST = process.env.VERYKEY_HOST || '127.0.0.1';
const CFG_FILE = path.join(V.DIR, 'webui.json');
const QR_PATH = path.join(__dirname, 'qrcode.min.js');

function loadJson(p, fb) { try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch (e) { return fb; } }
function saveJson(p, o) { try { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(o, null, 2), 'utf-8'); } catch (e) {} }

// 确保 vault 已初始化
try { V.loadVault(); } catch (e) {
  V.initMasterKey();
  V.saveVault({});
  V.audit('init', '-', 'webui');
}

const cfg = loadJson(CFG_FILE, {});

// ─── 主密码（Bitwarden 式解锁，轻量版）───────────
// 首次设置：/api/setup-pass；之后解锁：/api/unlock（10 分钟自动锁）
function hashPassword(pw, salt) { return crypto.scryptSync(pw, salt, 32).toString('hex'); }
let unlockedAt = 0;                       // 内存解锁态
const UNLOCK_TTL = 10 * 60 * 1000;        // 10 分钟
function isUnlocked() { return cfg.masterHash && (Date.now() - unlockedAt) < UNLOCK_TTL; }
function tryUnlock(pw) {
  if (!cfg.masterHash) return false;
  const h = hashPassword(pw || '', cfg.masterSalt);
  if (h === cfg.masterHash) { unlockedAt = Date.now(); return true; }
  return false;
}
function setMasterPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  cfg.masterHash = hashPassword(pw, salt);
  cfg.masterSalt = salt;
  saveJson(CFG_FILE, cfg);
  unlockedAt = Date.now();
}

// ─── TOTP（复用云桥逻辑）───────────────────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(s) {
  s = s.toUpperCase().replace(/=+$/g, '');
  let bits = 0, value = 0, out = [];
  for (const c of s) {
    const idx = B32.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function genSecret(len = 32) {
  const b = crypto.randomBytes(len);
  let s = '';
  for (const x of b) s += B32[x % 32];
  return s;
}
function totp(secret, timeStep = 30, digits = 6, drift = 0) {
  const key = base32Decode(secret);
  const counter = Math.floor((Date.now() + drift * 1000) / 1000 / timeStep);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(bin % Math.pow(10, digits)).padStart(digits, '0');
}
function verifyTotp(secret, code) {
  if (!/^\d{6}$/.test(code || '')) return false;
  for (const w of [0, -1, 1]) if (totp(secret, 30, 6, w * 30) === code) return true;
  return false;
}
let totpSecret = cfg.totpSecret || genSecret();
let totpBound = cfg.totpBound === true;
if (!cfg.totpSecret) { cfg.totpSecret = totpSecret; saveJson(CFG_FILE, cfg); }
function otpauthUri() {
  return `otpauth://totp/VeryKey:admin?secret=${totpSecret}&issuer=${encodeURIComponent('VeryKey')}`;
}

// ─── Session（无状态签名，重启不失效）──────────
const SESSION_SECRET = cfg.sessionSecret || crypto.randomBytes(32).toString('hex');
if (!cfg.sessionSecret) { cfg.sessionSecret = SESSION_SECRET; saveJson(CFG_FILE, cfg); }
function issueSession() {
  const exp = Date.now() + 7 * 24 * 3600 * 1000;
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function authed(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)__vk=([A-Za-z0-9._-]+)/);
  if (!m) return false;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return exp > Date.now();
  } catch (e) { return false; }
}

// ─── 页面 ──────────────────────────────────────
const LOGIN_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VeryKey · 安全验证</title><script src="/qrcode.min.js"></script><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter','Noto Sans SC',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(1200px 600px at 20% -10%,#0f3d2e 0%,transparent 55%),radial-gradient(900px 500px at 110% 110%,#1e3a5f 0%,transparent 50%),#0b0f1a;color:#e8ecf4;overflow:hidden}
.card{background:rgba(20,28,46,.72);backdrop-filter:blur(18px);border:1px solid rgba(255,255,255,.08);border-radius:22px;padding:40px 44px;width:390px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.logo .dot{width:14px;height:14px;border-radius:50%;background:linear-gradient(135deg,#34d399,#6366f1);box-shadow:0 0 18px rgba(52,211,153,.8)}
.logo span{font-size:17px;font-weight:600;letter-spacing:.5px}
h2{font-size:20px;font-weight:600;margin:16px 0 4px}
.sub{color:#8b94a7;font-size:13px;margin-bottom:22px;line-height:1.6}
.steps{display:flex;flex-direction:column;gap:12px;margin-bottom:24px}
.step{display:flex;gap:12px;align-items:flex-start}
.step .n{flex:0 0 24px;height:24px;border-radius:50%;background:rgba(52,211,153,.15);color:#34d399;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
.step .t{font-size:13px;color:#c2cadb;line-height:1.5}
#qrcode{display:flex;justify-content:center;background:#fff;padding:14px;border-radius:14px;margin:4px 0 18px}
#qrcode img{width:200px;height:200px;display:block}
.code-row{display:flex;gap:10px;justify-content:center;margin:6px 0 20px}
.code-row input{width:52px;height:60px;text-align:center;font-size:26px;font-weight:700;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:#e8ecf4;outline:none;transition:.15s;caret-color:#34d399}
.code-row input:focus{border-color:#34d399;background:rgba(52,211,153,.08)}
.btn{width:100%;height:50px;border:0;border-radius:12px;background:linear-gradient(135deg,#34d399,#0ea5e9);color:#04211a;font-size:16px;font-weight:700;cursor:pointer;transition:.15s}
.btn:hover{filter:brightness(1.1)}
.btn:disabled{opacity:.5;cursor:wait}
.msg{display:none;margin-top:14px;padding:10px 14px;border-radius:10px;font-size:13px}
.msg.err{display:block;background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.3)}
.foot{margin-top:22px;color:#5b6478;font-size:12px;text-align:center}
</style></head><body>
<div class="card">
  <div class="logo"><div class="dot"></div><span>VeryKey</span></div>
  <h2 id="title">安全验证</h2>
  <div class="sub" id="sub">正在检查绑定状态…</div>
  <div id="bindArea" style="display:none">
    <div class="steps">
      <div class="step"><div class="n">1</div><div class="t">打开手机验证器（Google Authenticator 等）</div></div>
      <div class="step"><div class="n">2</div><div class="t">扫描下方二维码添加 VeryKey</div></div>
      <div class="step"><div class="n">3</div><div class="t">输入 6 位动态码完成绑定</div></div>
    </div>
    <div id="qrcode"></div>
  </div>
  <div class="code-row">
    <input maxlength="1" id="c0"><input maxlength="1" id="c1"><input maxlength="1" id="c2"><input maxlength="1" id="c3"><input maxlength="1" id="c4"><input maxlength="1" id="c5">
  </div>
  <button class="btn" id="go">验证并进入</button>
  <div class="msg" id="msg"></div>
  <div class="foot">VeryKey · 本机受 TOTP 双重保护 · 验证码 30 秒刷新</div>
</div>
<script>
const inputs=[...document.querySelectorAll('.code-row input')];
inputs.forEach((el,i)=>{el.addEventListener('input',()=>{if(el.value&&i<5)inputs[i+1].focus()});
el.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!el.value&&i>0)inputs[i-1].focus()})});
async function api(p,body){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return r.json()}
(async()=>{
  const st=await api('/api/auth/status');
  if(!st.initialized){document.getElementById('sub').textContent='首次使用：初始化密钥库';document.getElementById('go').textContent='初始化并验证';}
  if(!st.bound){
    document.getElementById('bindArea').style.display='block';
    const q=await api('/api/auth/qr');
    new QRCode(document.getElementById('qrcode'),{text:q.uri,width:200,height:200});
    document.getElementById('sub').textContent='首次使用：先扫码绑定，再输入动态码';
  }
})();
document.getElementById('go').onclick=async()=>{
  const code=inputs.map(i=>i.value).join('');
  const r=await api('/api/auth/verify',{code});
  if(r.success){location.href='/'}else{document.getElementById('msg').className='msg err';document.getElementById('msg').textContent=r.error||'验证失败'}
};
</script></body></html>`;

const MAIN_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VeryKey · 密钥保险库</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter','Noto Sans SC',system-ui,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh;padding:20px}
.wrap{max-width:760px;margin:0 auto}
.top{display:flex;align-items:center;gap:10px;margin-bottom:18px;padding:14px 18px;background:#161b22;border:1px solid #30363d;border-radius:12px}
.top .dot{width:12px;height:12px;border-radius:50%;background:linear-gradient(135deg,#3fb950,#58a6ff);box-shadow:0 0 14px rgba(63,185,80,.6)}
.top h1{font-size:17px;font-weight:700}
.top .sp{flex:1}
.unlock{display:flex;gap:8px;align-items:center}
.unlock input{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:8px 12px;color:#e6edf3;font-size:13px;outline:none;width:170px}
.unlock input:focus{border-color:#3fb950}
.btn{border:0;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer;transition:.15s}
.btn.g{background:#238636;color:#fff}.btn.g:hover{filter:brightness(1.15)}
.btn.gray{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
.btn.gray:hover{background:#30363d}
.btn.d{background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.3)}
.badge{font-size:11px;padding:4px 10px;border-radius:20px;font-weight:600}
.badge.lock{background:#21262d;color:#8b949e;border:1px solid #30363d}
.badge.open{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.35)}
.add{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px;margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap}
.add input{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:9px 12px;color:#e6edf3;font-size:13px;outline:none}
.add input:focus{border-color:#58a6ff}
.add .nm{width:190px}.add .val{flex:1;min-width:200px}.add .nt{width:150px}
.search{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:10px 14px;color:#e6edf3;font-size:14px;outline:none;margin-bottom:12px}
.search:focus{border-color:#58a6ff}
.item{display:flex;align-items:center;gap:12px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 16px;margin-bottom:8px}
.item .nm{font-family:'JetBrains Mono',monospace;font-size:14px;color:#58a6ff;min-width:180px;font-weight:600}
.item .v{font-family:'JetBrains Mono',monospace;font-size:13px;color:#8b949e;flex:1}
.item .note{color:#6e7681;font-size:12px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item .ops{display:flex;gap:6px}
.item .ops button{background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:7px;padding:5px 10px;font-size:12px;cursor:pointer}
.item .ops button:hover{border-color:#58a6ff;color:#58a6ff}
.item .ops button.del:hover{border-color:#f85149;color:#f85149}
.empty{color:#6e7681;text-align:center;padding:36px;font-size:13px}
.hint{color:#6e7681;font-size:12px;margin-bottom:14px;line-height:1.7}
.hint code{background:#21262d;padding:2px 7px;border-radius:5px;color:#3fb950}
.setup{background:#161b22;border:1px solid rgba(88,166,255,.35);border-radius:12px;padding:18px;margin-bottom:14px}
.setup h3{font-size:14px;margin-bottom:6px;color:#58a6ff}
.setup p{color:#8b949e;font-size:12px;margin-bottom:12px}
.setup .row{display:flex;gap:8px}
.setup input{flex:1;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:9px 12px;color:#e6edf3;font-size:13px;outline:none}
.copy-ok{color:#3fb950;font-size:11px;margin-left:4px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#238636;color:#fff;padding:10px 20px;border-radius:10px;font-size:13px;opacity:0;transition:.3s;pointer-events:none}
.toast.show{opacity:1}
</style></head><body>
<div class="wrap">
  <div class="top">
    <div class="dot"></div><h1>VeryKey</h1>
    <div class="sp"></div>
    <div id="lockArea"></div>
  </div>
  <div id="setupArea"></div>
  <div class="hint">智能体调用：<code>verykey run 变量名 -- 命令</code> · 明文需主密码解锁后复制</div>
  <div class="add">
    <input class="nm" id="nm" placeholder="变量名 e.g. GITHUB_TOKEN" autocomplete="off" spellcheck="false">
    <input class="val" id="val" placeholder="密钥 / 密码值" autocomplete="off" type="password">
    <button class="btn gray" onclick="gen()" title="生成随机值">🎲</button>
    <input class="nt" id="nt" placeholder="备注" autocomplete="off">
    <button class="btn g" onclick="addKey()">保存</button>
  </div>
  <input class="search" id="q" placeholder="搜索变量名…" oninput="render()">
  <div id="list"></div>
</div>
<div class="toast" id="toast"></div>
<script>
async function j(p,opt){const r=await fetch(p,opt);if(r.status===401){location.href='/login';throw 0}return r.json()}
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;')}
function toast(t){const e=document.getElementById('toast');e.textContent=t;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),1600)}
async function copy(t){try{await navigator.clipboard.writeText(t);toast('已复制')}catch(e){toast('复制失败')}}
function gen(){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',b=crypto.getRandomValues(new Uint8Array(32));let s='';for(const x of b)s+=a[x%a.length];document.getElementById('val').value=s}
let keys=[],q='';
async function loadKeys(){const d=await j('/api/keys');keys=d.items;render()}
function render(){
  q=document.getElementById('q').value.toLowerCase();
  const el=document.getElementById('list');
  const list=keys.filter(k=>k.name.toLowerCase().includes(q)||(k.note||'').toLowerCase().includes(q));
  if(!list.length){el.innerHTML='<div class="empty">'+ (keys.length?'没有匹配的密钥':'还没有密钥 — 在顶部输入变量名和值，点「保存」') +'</div>';return}
  el.innerHTML=list.map(k=>
    '<div class="item"><div class="nm">'+esc(k.name)+'</div><div class="v">'+esc(k.masked)+'</div><div class="note">'+esc(k.note)+'</div>'+
    '<div class="ops"><button onclick="copy(\''+k.name+'\')" title="复制变量名">名</button>'+
    '<button class="reveal" id="rv_'+k.name+'" onclick="copyValue(\''+k.name+'\')" title="复制明文（需解锁）">钥</button>'+
    '<button class="del" onclick="delKey(\''+k.name+'\')">✕</button></div></div>').join('');
  paintLock();
}
async function copyValue(n){const r=await j('/api/keys/'+encodeURIComponent(n)+'/plain');if(r.ok&&r.value){copy(r.value)}else{alert(r.error||'需要先解锁')}}
async function delKey(n){if(!confirm('删除 '+n+'？'))return;const r=await j('/api/keys/'+encodeURIComponent(n),{method:'DELETE'});if(r.success){toast('已删除');loadKeys()}}
async function addKey(){
  const nm=document.getElementById('nm').value.trim(),val=document.getElementById('val').value,nt=document.getElementById('nt').value.trim();
  if(!nm||!val)return toast('变量名和值必填');
  const r=await j('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:nm,value:val,note:nt})});
  if(r.success){document.getElementById('nm').value='';document.getElementById('val').value='';document.getElementById('nt').value='';toast('已保存');loadKeys()}
  else alert(r.error||'保存失败');
}
async function paintLock(){
  const st=await j('/api/state').catch(()=>({unlocked:false,hasMaster:false}));
  const la=document.getElementById('lockArea');
  if(!st.hasMaster){
    const sa=document.getElementById('setupArea');
    sa.innerHTML='<div class="setup"><h3>设置主密码</h3><p>主密码用于解锁查看明文（10 分钟自动锁定）。与 TOTP 登录相互独立，请牢记。</p>'+
    '<div class="row"><input id="sp1" type="password" placeholder="设置主密码"><input id="sp2" type="password" placeholder="确认主密码"><button class="btn g" onclick="setupPass()">设置</button></div></div>';
    la.innerHTML='<span class="badge lock">🔒 未设置主密码</span>';return;
  }
  document.getElementById('setupArea').innerHTML='';
  if(st.unlocked){
    la.innerHTML='<span class="badge open">🔓 已解锁</span> <button class="btn gray" onclick="lock()">锁定</button>';
  }else{
    la.innerHTML='<div class="unlock"><input id="pw" type="password" placeholder="主密码" onkeydown="if(event.key===\'Enter\')unlock()"><button class="btn g" onclick="unlock()">解锁</button></div>';
  }
}
let uiTimer=null;
async function refresh(){await paintLock();const st=await j('/api/state');if(!st.unlocked){document.querySelectorAll('.reveal').forEach(b=>b.style.opacity='.35')}}
async function unlock(){const pw=document.getElementById('pw').value;const r=await j('/api/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.success){toast('已解锁');paintLock()}else{alert('主密码错误')}}
async function lock(){await j('/api/lock',{method:'POST'});paintLock()}
async function setupPass(){const a=document.getElementById('sp1').value,b=document.getElementById('sp2').value;if(!a||a.length<4)return alert('主密码至少 4 位');if(a!==b)return alert('两次输入不一致');const r=await j('/api/setup-pass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:a})});if(r.success){toast('主密码已设置');refresh()}else alert(r.error||'设置失败')}
setInterval(refresh,30000);
loadKeys();
</script></body></html>`;

// ─── HTTP ──────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const send = (code, obj, head = {}) => {
    res.writeHead(code, { 'Content-Type': 'application/json', ...head });
    res.end(JSON.stringify(obj));
  };
  const body = () => new Promise((resolve) => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } }); });

  if (url === '/qrcode.min.js') {
    try { res.writeHead(200, { 'Content-Type': 'application/javascript' }); res.end(fs.readFileSync(QR_PATH)); } catch (e) { send(404, {}); }
    return;
  }
  if (url === '/login' || url === '/') {
    const ok = authed(req);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(ok ? MAIN_HTML : LOGIN_HTML);
    return;
  }

  // API
  if (url === '/api/auth/status') { send(200, { initialized: true, bound: totpBound }); return; }
  if (url === '/api/auth/qr') {
    if (totpBound) return send(200, { bound: true });
    return send(200, { uri: otpauthUri(), bound: false });
  }
  if (url === '/api/auth/verify') {
    const b = await body();
    if (!verifyTotp(totpSecret, b.code)) return send(200, { success: false, error: '验证码错误或已过期' });
    if (!totpBound) { totpBound = true; cfg.totpBound = true; saveJson(CFG_FILE, cfg); }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `__vk=${issueSession()}; HttpOnly; Path=/; Max-Age=604800` });
    res.end(JSON.stringify({ success: true }));
    return;
  }
  if (url === '/api/logout') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': '__vk=; HttpOnly; Path=/; Max-Age=0' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  if (!authed(req)) return send(401, { error: '未认证' });

  if (url === '/api/state') {
    return send(200, { unlocked: isUnlocked(), hasMaster: !!cfg.masterHash });
  }
  if (url === '/api/setup-pass') {
    const b = await body();
    if (cfg.masterHash) return send(200, { success: false, error: '主密码已设置' });
    if (!b.password || String(b.password).length < 4) return send(200, { success: false, error: '主密码至少 4 位' });
    setMasterPassword(String(b.password));
    V.audit('setup-master-pass', '-', 'webui');
    return send(200, { success: true });
  }
  if (url === '/api/unlock') {
    const b = await body();
    if (tryUnlock(b.password)) { V.audit('unlock', '-', 'webui'); return send(200, { success: true }); }
    V.audit('unlock-fail', '-', 'webui');
    return send(200, { success: false, error: '主密码错误' });
  }
  if (url === '/api/lock') {
    unlockedAt = 0;
    return send(200, { success: true });
  }
  if (url === '/api/keys' && req.method === 'GET') {
    const vault = V.loadVault();
    const items = Object.keys(vault).sort().map(n => ({ name: n, masked: V.mask(vault[n].value), note: vault[n].note || '', createdAt: vault[n].createdAt, updatedAt: vault[n].updatedAt }));
    return send(200, { items });
  }
  if (url === '/api/keys' && req.method === 'POST') {
    const b = await body();
    const name = (b.name || '').trim();
    if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(name)) return send(200, { success: false, error: '变量名需为 UPPER_SNAKE_CASE（如 GITHUB_TOKEN）' });
    if (!b.value) return send(200, { success: false, error: '值不能为空' });
    const vault = V.loadVault();
    vault[name] = { value: String(b.value), note: b.note || '', createdAt: (vault[name] && vault[name].createdAt) || new Date().toISOString(), updatedAt: new Date().toISOString() };
    V.saveVault(vault);
    V.audit('add/update', name, 'webui');
    return send(200, { success: true });
  }
  const mp = url.match(/^\/api\/keys\/([^/]+)\/plain$/);
  if (mp) {
    const name = decodeURIComponent(mp[1]);
    if (!isUnlocked()) return send(200, { ok: false, error: '需要主密码解锁' });
    const vault = V.loadVault();
    if (!vault[name]) return send(200, { ok: false, error: '未找到' });
    V.audit('reveal', name, 'webui');
    return send(200, { ok: true, value: vault[name].value });
  }
  const m = url.match(/^\/api\/keys\/([^/]+)$/);
  if (m && req.method === 'DELETE') {
    const name = decodeURIComponent(m[1]);
    const vault = V.loadVault();
    if (!vault[name]) return send(200, { success: false, error: '未找到' });
    delete vault[name];
    V.saveVault(vault);
    V.audit('delete', name, 'webui');
    return send(200, { success: true });
  }
  if (m && req.method === 'PUT') {
    const b = await body();
    const name = decodeURIComponent(m[1]);
    const vault = V.loadVault();
    if (!vault[name]) return send(200, { success: false, error: '未找到' });
    if (b.value) vault[name].value = String(b.value);
    if (b.note !== undefined) vault[name].note = String(b.note);
    vault[name].updatedAt = new Date().toISOString();
    V.saveVault(vault);
    V.audit('update', name, 'webui');
    return send(200, { success: true });
  }
  if (url === '/api/audit') {
    return send(200, { items: V.readAudit(100) });
  }
  send(404, { error: 'not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`🔐 VeryKey WebUI: http://${HOST}:${PORT}（TOTP 认证）`);
  console.log(`   数据目录: ${V.DIR}`);
  if (!totpBound) console.log(`   首次访问 /login 扫码绑定（otpauth://totp/VeryKey:admin）`);
});