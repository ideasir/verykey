#!/usr/bin/env node
/**
 * dsh-public 认证代理（TOTP 版）：
 *   - 首次访问：显示二维码绑定手机验证器（Google Authenticator 等）
 *   - 已绑定：输入 6 位动态码登录（cookie 7 天免登）
 *   - 认证通过后转发 → 127.0.0.1:3080（Host 改写为 dsh.local 供 DSH trusted-host 放行）
 * 零依赖。环境变量：DP_PORT / DP_TRUST_HOST / DP_DIR
 */
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.DP_PORT || '9443', 10);
const UP_HOST = process.env.DP_UP_HOST || '127.0.0.1';
const UP_PORT = parseInt(process.env.DP_UP_PORT || '3080', 10);
const TRUST_HOST = process.env.DP_TRUST_HOST || 'dsh.local';
const DP_DIR = process.env.DP_DIR || '/opt/dsh-public';
const LOG = process.env.DP_LOG || '/tmp/dsh-public-proxy.log';

const AUTH_FILE = path.join(DP_DIR, 'auth.json');
const CFG_FILE = path.join(DP_DIR, 'config.json');

function loadCfg() { try { return JSON.parse(fs.readFileSync(CFG_FILE, 'utf-8')); } catch (e) { return {}; } }
// 注入脚本：临时域名提示横幅（仅临时域名模式注入）
function bannerInject() {
  const cfg = loadCfg();
  if (!cfg || cfg.mode === 'domain') return null; // 永久域名模式不提示
  const url = cfg.publicUrl || '';
  return `<script>
(function(){
  try{
    if(localStorage.getItem('dshpub_dismissed')) return;
    var b=document.createElement('div');
    b.id='dshpub-banner';
    b.innerHTML='<div style="display:flex;align-items:center;gap:12px;padding:12px 18px;background:linear-gradient(135deg,#7c2d12,#9a3412);color:#fde68a;font:600 13px/1.5 system-ui;box-shadow:0 4px 24px rgba(0,0,0,.35);border-bottom:1px solid rgba(251,191,36,.3)"><span style="font-size:16px">⚠️</span><div style="flex:1"><b>当前使用临时域名</b>（${url||'未知'}）· 临时域名可能随时变更，建议绑定永久域名后更稳定。<span id="dshpub-how" style="color:#fbbf24;text-decoration:underline;cursor:pointer">绑定永久域名</span></div><span id="dshpub-x" style="cursor:pointer;opacity:.8;font-size:18px;padding:0 4px">✕</span></div><div id="dshpub-detail" style="display:none;background:#0c1220;color:#cbd5e1;font:13px/1.7 system-ui;padding:14px 18px">在服务器上执行：<code style="background:#1e293b;padding:2px 8px;border-radius:6px;color:#7dd3fc">sudo dsh-public bind --domain 你的域名.com</code><br>（需先把域名 DNS 解析到本机公网 IP。绑定后临时域名失效，此提示不再出现，TOTP 验证器绑定保持不变）</div>';
    b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:999999;font-family:system-ui';
    b.querySelector('#dshpub-how').onclick=function(){var d=b.querySelector('#dshpub-detail');d.style.display=d.style.display==='none'?'block':'none'};
    b.querySelector('#dshpub-x').onclick=function(){b.remove();try{localStorage.setItem('dshpub_dismissed','1')}catch(e){}};
    document.documentElement.appendChild(b);
  }catch(e){}
})();
</script>`;
}

function log(m) { try { fs.appendFileSync(LOG, `[${new Date().toISOString()}] ${m}\n`); } catch (e) {} }
function loadAuth() { try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')); } catch (e) { return {}; } }
function saveAuth(a) { fs.mkdirSync(DP_DIR, { recursive: true }); fs.writeFileSync(AUTH_FILE, JSON.stringify(a, null, 2), { mode: 0o600 }); }

// ─── TOTP（云桥同款）───────────────────────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(s) {
  s = s.toUpperCase().replace(/=+$/g, '');
  let bits = 0, value = 0, out = [];
  for (const c of s) { const idx = B32.indexOf(c); if (idx < 0) continue; value = (value << 5) | idx; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
  return Buffer.from(out);
}
function genSecret(len = 32) { const b = crypto.randomBytes(len); let s = ''; for (const x of b) s += B32[x % 32]; return s; }
function totp(secret, timeStep = 30, digits = 6, driftSec = 0) {
  const key = base32Decode(secret);
  const counter = Math.floor((Date.now() + driftSec * 1000) / 1000 / timeStep);
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
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
let auth = loadAuth();
if (!auth.secret) { auth = { secret: genSecret(), bound: false, sessionSecret: crypto.randomBytes(32).toString('hex') }; saveAuth(auth); }
function otpauthUri() { return `otpauth://totp/DSH:admin?secret=${auth.secret}&issuer=${encodeURIComponent('DSH公网')}`; }

// ─── 无状态 session（7 天）─────────────────────
function issueSession() {
  const exp = Date.now() + 7 * 24 * 3600 * 1000;
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', auth.sessionSecret).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function authed(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)__dp=([A-Za-z0-9._-]+)/);
  if (!m) return false;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', auth.sessionSecret).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString()); return exp > Date.now(); } catch (e) { return false; }
}

// ─── 登录页（云桥同款风格）──────────────────────
const LOGIN_HTML = () => `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH 公网访问 · 安全验证</title><script src="/__dp/qrcode"></script><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter','Noto Sans SC',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(1200px 600px at 20% -10%,#312e81 0%,transparent 55%),radial-gradient(900px 500px at 110% 110%,#0e7490 0%,transparent 50%),#0b0f1a;color:#e8ecf4;overflow:hidden}
.card{background:rgba(20,28,46,.72);backdrop-filter:blur(18px);border:1px solid rgba(255,255,255,.08);border-radius:22px;padding:40px 44px;width:400px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.logo .dot{width:14px;height:14px;border-radius:50%;background:linear-gradient(135deg,#818cf8,#22d3ee);box-shadow:0 0 18px rgba(129,140,248,.8)}
.logo span{font-size:17px;font-weight:600;letter-spacing:.5px}
h2{font-size:20px;font-weight:600;margin:16px 0 4px}
.sub{color:#8b94a7;font-size:13px;margin-bottom:20px;line-height:1.6}
.steps{display:flex;flex-direction:column;gap:12px;margin-bottom:20px}
.step{display:flex;gap:12px;align-items:flex-start}
.step .n{flex:0 0 24px;height:24px;border-radius:50%;background:rgba(129,140,248,.15);color:#a5b4fc;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
.step .t{font-size:13px;color:#c2cadb;line-height:1.5}
#qrcode{display:flex;justify-content:center;background:#fff;padding:14px;border-radius:14px;margin:4px 0 16px}
#qrcode img{width:200px;height:200px;display:block}
.code-row{display:flex;gap:10px;justify-content:center;margin:6px 0 16px}
.code-row input{width:52px;height:60px;text-align:center;font-size:26px;font-weight:700;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:#e8ecf4;outline:none;caret-color:#818cf8}
.code-row input:focus{border-color:#818cf8}
.btn{width:100%;height:50px;border:0;border-radius:12px;background:linear-gradient(135deg,#818cf8,#22d3ee);color:#0b0f1a;font-size:16px;font-weight:700;cursor:pointer}
.msg{display:none;margin-top:14px;padding:10px;border-radius:10px;font-size:13px}
.msg.err{display:block;background:rgba(239,68,68,.12);color:#fca5a5}
.foot{margin-top:18px;color:#5b6478;font-size:12px;text-align:center}
</style></head><body>
<div class="card">
  <div class="logo"><div class="dot"></div><span>DSH 公网访问</span></div>
  <h2 id="title">安全验证</h2>
  <div class="sub" id="sub">${auth.bound ? '请输入手机验证器上的 6 位动态码' : '首次使用：先扫码绑定手机验证器，再输入动态码'}</div>
  ${auth.bound ? '' : `
  <div class="steps">
    <div class="step"><div class="n">1</div><div class="t">打开手机验证器（Google Authenticator 等）</div></div>
    <div class="step"><div class="n">2</div><div class="t">扫描下方二维码添加「DSH公网」</div></div>
    <div class="step"><div class="n">3</div><div class="t">输入 6 位动态码完成绑定</div></div>
  </div>`}
  ${auth.bound ? '' : '<div id="qrcode-wrap"><div id="qrcode"></div></div>'}
  <div class="code-row" id="row">
    <input maxlength="1" id="c0"><input maxlength="1" id="c1"><input maxlength="1" id="c2"><input maxlength="1" id="c3"><input maxlength="1" id="c4"><input maxlength="1" id="c5">
  </div>
  <button class="btn" id="go">验证并进入</button>
  <div class="msg" id="msg"></div>
  <div class="foot">DSH 公网访问 · 手机验证器动态码 · 30 秒刷新</div>
</div>
<script>
${auth.bound ? '' : `new QRCode(document.getElementById('qrcode'), { text: ${JSON.stringify(otpauthUri())}, width: 200, height: 200 });`}
const inputs=[...document.querySelectorAll('.code-row input')];
inputs.forEach((el,i)=>{el.addEventListener('input',()=>{if(el.value&&i<5)inputs[i+1].focus()});el.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!el.value&&i>0)inputs[i-1].focus()})});
document.getElementById('go').onclick=async()=>{
  const code=inputs.map(i=>i.value).join('');
  const r=await fetch('/__dp/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
  const d=await r.json();
  if(d.success){location.href='/'}else{document.getElementById('msg').className='msg err';document.getElementById('msg').textContent='验证码错误或已过期'}
};
</script></body></html>`;

// ─── HTTP ──────────────────────────────────────
http.createServer((req, res) => {
  const url = req.url.split('?')[0];

  // 静态：二维码库（换行转义）
  if (url === '/__dp/qrcode') {
    try { res.writeHead(200, { 'Content-Type': 'application/javascript' }); res.end(fs.readFileSync(path.join(DP_DIR, 'qrcode.min.js'))); } catch (e) { res.writeHead(404); res.end('missing qrcode.min.js'); }
    return;
  }
  // 登录页
  if (url === '/__dp/login') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(LOGIN_HTML()); return; }
  // 验证 TOTP
  if (url === '/__dp/verify' && req.method === 'POST') {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => {
      let code = '';
      try { code = JSON.parse(d).code || ''; } catch (e) {}
      if (!verifyTotp(auth.secret, code)) { log('verify fail from ' + req.socket.remoteAddress); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ success: false })); return; }
      if (!auth.bound) { auth.bound = true; saveAuth(auth); log('TOTP 首次绑定成功'); }
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `__dp=${issueSession()}; HttpOnly; Path=/; Max-Age=604800` });
      res.end(JSON.stringify({ success: true }));
    });
    return;
  }

  // 认证放行
  if (!authed(req)) {
    res.writeHead(302, { Location: '/__dp/login' });
    res.end();
    return;
  }
  // 转发 DSH：Host/Origin 原样传 127.0.0.1:3080（DSH 当本地访问，settings 等敏感 API 才放行）
  // 备注：早期用 Host 改写 dsh.local 绕 browser-trust，但 settings.* 等 API 要求真本地（Host=127.0.0.1）
  const headers = Object.assign({}, req.headers, { host: UP_HOST + ':' + UP_PORT, origin: 'http://' + UP_HOST + ':' + UP_PORT });
  const up = http.request({ host: UP_HOST, port: UP_PORT, path: req.url, method: req.method, headers }, (ur) => {
    const ct = (ur.headers['content-type'] || '').toString();
    const inject = bannerInject();
    if (inject && ct.includes('text/html') && req.method === 'GET') {
      const chunks = [];
      ur.on('data', c => chunks.push(c));
      ur.on('end', () => {
        let body = Buffer.concat(chunks).toString('utf-8');
        if (body.includes('</head>')) {
          body = body.replace('</head>', inject + '</head>');
          const hd = Object.assign({}, ur.headers); delete hd['content-length'];
          res.writeHead(ur.statusCode, hd);
          res.end(body);
        } else {
          res.writeHead(ur.statusCode, ur.headers);
          res.end(Buffer.concat(chunks));
        }
      });
      return;
    }
    res.writeHead(ur.statusCode, ur.headers);
    ur.pipe(res);
  });
  up.on('error', (e) => { log('upstream error: ' + e.message); res.writeHead(502); res.end('bad gateway'); });
  req.pipe(up);
}).listen(PORT, '127.0.0.1', () => {
  log(`listening http://127.0.0.1:${PORT} -> ${UP_HOST}:${UP_PORT} (TOTP auth)`);
  console.log(`dsh-public proxy: http://127.0.0.1:${PORT} -> ${UP_HOST}:${UP_PORT} (TOTP)`);
});