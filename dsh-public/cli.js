#!/usr/bin/env node
/**
 * dsh-public v4 — DSH 公网访问插件
 *
 *   dsh-public bind --domain x.com   绑定自有域名（推荐：全自动 DNS验证→nginx→证书→HTTPS）
 *   dsh-public bind                  交互输入域名（安装后引导流程）
 *   dsh-public status                状态
 *   dsh-public stop                  停止公网访问
 *   dsh-public auth-reset            重置 TOTP 绑定
 *
 * 架构（全部 systemd 常驻，断线自愈）：
 *   nginx(443,证书) → proxy(dsh-proxy,TOTP认证) → DSH(dsh,仅本地)   [SSE 直通]
 */
'use strict';
// 需要 root（systemd/nginx/证书操作）
if (typeof process.getuid === 'function' && process.getuid && process.getuid() !== 0) {
  console.error('✗ 需要 root 权限，请用: sudo dsh-public start');
  process.exit(1);
}
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');
const crypto = require('crypto');

const DIR = '/opt/dsh-public';
const CONFIG = path.join(DIR, 'config.json');
const PROXY = path.join(DIR, 'proxy.js');
const PROXY_PORT = 9443;
const DSH_PORT = 3080;
const TRUST_HOST = 'dsh.local';
const TUNNEL_LOG = '/tmp/dsh-public-tunnel.log';

function loadCfg() { try { return JSON.parse(fs.readFileSync(CONFIG, 'utf-8')); } catch (e) { return {}; } }
function saveCfg(c) { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(CONFIG, JSON.stringify(c, null, 2), { mode: 0o600 }); }
function log(m) { console.log('  ' + m); }
function sh(cmd) { try { return execSync(cmd, { timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim(); } catch (e) { return ''; } }

// ─── systemd unit 模板 ─────────────────────────
function dshUnit(trustedHost, port) {
  return `[Unit]
Description=DSH WebUI (dsh-public managed)
After=network.target

[Service]
ExecStart=/usr/bin/dsh --profile web --trusted-host ${trustedHost} --port ${port}
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
`;
}
function proxyUnit() {
  return `[Unit]
Description=dsh-public proxy
After=network.target

[Service]
ExecStart=/usr/bin/node ${PROXY}
Environment=DP_PORT=${PROXY_PORT}
Environment=DP_TRUST_HOST=${TRUST_HOST}
Environment=DP_DIR=${DIR}
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
`;
}
const TUNNEL_UNIT = `[Unit]
Description=dsh-public cloudflared tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --url http://127.0.0.1:${PROXY_PORT} --no-autoupdate
Restart=always
RestartSec=3
StandardOutput=append:${TUNNEL_LOG}
StandardError=append:${TUNNEL_LOG}
User=root

[Install]
WantedBy=multi-user.target
`;

function writeUnit(name, content) {
  fs.writeFileSync('/tmp/dsh-public-' + name + '.unit', content);
  sh('cp /tmp/dsh-public-' + name + '.unit /etc/systemd/system/' + name + '.service');
}
function svcActive(name) { return sh(`systemctl is-active ${name} 2>/dev/null`) === 'active'; }
function getTunnelUrl() {
  try {
    const s = fs.readFileSync(TUNNEL_LOG, 'utf-8');
    const m = s.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/g);
    return m ? m[m.length - 1] : null;
  } catch (e) { return null; }
}

// ─── 命令 ──────────────────────────────────────
function parseArgs(argv) {
  const a = {}; for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) { const k = argv[i].slice(2); a[k] = (argv[i + 1] && !argv[i + 1].startsWith('--')) ? argv[i + 1] : true; }
  return a;
}
function ask(prompt) {
  return new Promise((resolve) => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); rl.question(prompt, (a) => { rl.close(); resolve(a.trim()); }); });
}

async function cmdStart(argv) {
  const opt = parseArgs(argv);
  const cfg = loadCfg();
  // TOTP 认证：无需密码，首次访问页面扫码绑定手机验证器

  // 确保 proxy.js 存在
  if (!fs.existsSync(PROXY)) return console.error('✗ 缺少 ' + PROXY + '（插件未完整安装）');
  sh('node --check ' + PROXY);
  // 确保 cloudflared
  if (!sh('which cloudflared')) return console.error('✗ 未找到 cloudflared，请先安装（插件安装脚本会自动处理）');

  const step = (n, t, ok) => console.log(`  [${ok ? '✓' : '…'}] ${t}`);
  console.log('');
  console.log('  🚀 正在开启 DSH 公网访问...');
  console.log('');
  // 1/4 配置
  step(1, '配置认证代理与 DSH 服务...');
  writeUnit('dsh', dshUnit(TRUST_HOST, DSH_PORT));
  writeUnit('dsh-proxy', proxyUnit());
  writeUnit('dsh-tunnel', TUNNEL_UNIT);
  cfg.mode = 'tunnel';
  saveCfg(cfg);
  sh('systemctl daemon-reload');
  sh('systemctl enable dsh dsh-proxy dsh-tunnel >/dev/null 2>&1');
  console.log('  [✓] 配置完成');

  // 2/4 启动服务
  step(2, '启动 DSH / 认证代理 / 隧道服务...');
  sh('systemctl restart dsh-proxy dsh dsh-tunnel');
  sh('sleep 3');
  const ok1 = svcActive('dsh') && svcActive('dsh-proxy') && svcActive('dsh-tunnel');
  console.log('  [' + (ok1 ? '✓' : '⚠') + '] 服务已 ' + (ok1 ? '全部运行' : '启动中'));

  // 3/4 申请临时域名（进度动画）
  step(3, '申请临时域名（连接 Cloudflare 边缘）...');
  const phases = ['正在连接 Cloudflare 边缘节点...', '正在建立加密隧道...', '正在分配临时域名...', '正在验证连通性...'];
  let url = getTunnelUrl();
  let phase = 0, ticks = 0;
  const sleepM = (ms) => new Promise(r => setTimeout(r, ms));
  while (!url && phase < phases.length) {
    const pct = Math.min(100, Math.round(((phase + 1) / 4) * 100));
    const bar = '█'.repeat(Math.floor(pct / 10)) + '░'.repeat(10 - Math.floor(pct / 10));
    process.stdout.write('\r\u001b[K  ⏳ ' + bar + ' ' + pct + '%  ' + phases[phase] + '   ');
    await sleepM(2000); ticks++;
    if (ticks >= 5) { phase = Math.min(phase + 1, 3); ticks = 0; }
    url = getTunnelUrl();
  }
  process.stdout.write('\r\u001b[K');
  if (url) console.log('  [✓] 临时域名已分配');
  else { console.log('  [⚠] 未就绪（看 ' + TUNNEL_LOG + '，可稍后 dsh-public tunnel 重取）'); }

  // 4/4 验证
  step(4, '验证公网可达性...');
  let reach = '';
  if (url) { try { const r = execSync(`curl -s -k -m 10 -o /dev/null -w "%{http_code}" ${url}/__dp/login`, { timeout: 15000 }).toString().trim(); reach = '认证页 HTTP ' + r; } catch (e) { reach = '首次连接建立中'; } }
  console.log('  [✓] 验证完成（' + reach + '）');

  cfg.publicUrl = url; saveCfg(cfg);
  console.log('');
  console.log('  ' + '='.repeat(54));
  console.log('   ✅ DSH 公网访问已开启！');
  console.log('');
  if (url) {
    console.log('   ➜  公网地址（浏览器打开即用）:');
    console.log('       ' + url);
  } else {
    console.log('   ⚠️  临时域名未就绪，稍后执行: sudo dsh-public tunnel');
  }
  console.log('');
  console.log('   首次访问: 页面会显示二维码，用手机验证器扫码绑定后输入动态码即可');
  console.log('');
  console.log('   绑定永久域名: sudo dsh-public bind --domain 你的域名');
  console.log('   停止访问:     sudo dsh-public stop');
  console.log('  ' + '='.repeat(54));
}

async function cmdBind(argv) {
  const opt = parseArgs(argv);
  let domain = opt.domain || '';
  if (!domain) {
    const a = await ask('请输入已解析到本机公网 IP 的域名（如 dsh.example.com）: ');
    domain = (a || '').trim();
  }
  if (!domain) return console.error('✗ 需要域名');
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(domain)) return console.error('✗ 域名格式不正确: ' + domain);
  await setupDomain(domain);
}

async function setupDomain(domain) {
  const cfg = loadCfg();
  const sleepM = (ms) => new Promise(r => setTimeout(r, ms));
  console.log('');
  console.log('  📡 正在绑定域名 ' + domain + ' ...');
  console.log('');
  const step = (n, t, ok) => console.log('  [' + (ok ? '✓' : '…') + '] 第 ' + n + ' 步：' + t);

  // ── 1/5 DNS 解析验证 ──
  step(1, '验证域名解析（DNS）...');
  const myip = sh("curl -s -m 10 https://ifconfig.me/ || curl -s -m 10 https://api.ipify.org/ || echo ''").trim();
  const dnsA = sh(`dig +short ${domain} A 2>/dev/null | head -1`).trim() || sh(`nslookup ${domain} 2>/dev/null | grep -A1 'Name:' | grep Address | awk '{print $2}' | head -1`).trim();
  let dnsOK = false, hint = '';
  if (dnsA && myip && dnsA === myip) { dnsOK = true; hint = '解析 ' + dnsA + ' = 本机 ' + myip + ' ✅'; }
  else if (dnsA && !myip) { dnsOK = true; hint = '解析 ' + dnsA + '（未取到本机 IP，跳过比对）'; }
  else if (!dnsA) { hint = '未查到 A 记录——请先到域名服务商把 ' + domain + ' 解析到本机公网 IP（' + (myip || '查询本机 IP 失败') + '）'; }
  else { hint = '解析 ' + dnsA + ' ≠ 本机 ' + myip + ' ——请改为解析到本机公网 IP'; }
  if (dnsOK) console.log('  [✓] DNS 检查通过（' + hint + '）');
  else {
    console.log('  [⚠] ' + hint);
    const c = await ask('    解析可能还没生效/不一致，仍要继续绑定吗？(y/N) ');
    if (c.toLowerCase() !== 'y') { console.log('  ✗ 已取消。请先解析域名后重试: sudo dsh-public bind'); return; }
  }

  // ── 2/5 nginx 配置 ──
  step(2, '配置 nginx 反向代理...');
  const certDir = DIR + '/cert';
  fs.mkdirSync(certDir, { recursive: true });
  const conf = `# dsh-public: ${domain}
server {
    listen 80;
    server_name ${domain};
    location /.well-known/acme-challenge/ { root /var/www/dsh-public; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${domain};
    ssl_certificate     ${certDir}/${domain}.pem;
    ssl_certificate_key ${certDir}/${domain}.key;
    proxy_buffering off;
    proxy_read_timeout 3600s;
    location / {
        proxy_pass http://127.0.0.1:${PROXY_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
  fs.writeFileSync('/tmp/dsh-public-domain.conf', conf);
  const sitesDir = fs.existsSync('/etc/nginx/sites-enabled') ? '/etc/nginx/sites-enabled' : '/etc/nginx/conf.d';
  sh(`cp /tmp/dsh-public-domain.conf ${sitesDir}/dsh-public.conf`);
  sh('mkdir -p /var/www/dsh-public');
  console.log('  [✓] nginx 配置已写入（' + sitesDir + '/dsh-public.conf）');

  // ── 3/5 证书 ──
  step(3, '申请 HTTPS 证书（acme.sh，可能需要 1-2 分钟）...');
  let acme = sh('which acme.sh') || sh('ls ~/.acme.sh/acme.sh 2>/dev/null');
  if (!acme && !sh('ls /root/.acme.sh/acme.sh 2>/dev/null')) {
    console.log('  … 未检测到 acme.sh，自动安装中...');
    sh("curl -sL https://get.acme.sh | sh -s email=dsh@example.com >/dev/null 2>&1 || curl -sL https://gh-proxy.com/https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s email=dsh@example.com >/dev/null 2>&1");
    sh('/root/.acme.sh/acme.sh --register-account -m dsh@example.com >/dev/null 2>&1 || true');
  }
  acme = sh('ls /root/.acme.sh/acme.sh 2>/dev/null') || sh('ls ~/.acme.sh/acme.sh 2>/dev/null') || sh('which acme.sh 2>/dev/null');
  if (!acme) { console.log('  [⚠] acme.sh 安装失败，改用自签证书（浏览器会有安全提示；后续可手动配证书）'); }
  let certOk = false;
  if (acme) {
    sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null');
    // 修复1：明确用 Let's Encrypt（acme.sh 默认 ZeroSSL 在某些网络卡死）
    // 修复2：注册账号用 admin@域名（默认 example.com 邮箱被 LE 拒绝）
    sh('rm -f /root/.acme.sh/account.conf');
    sh(`${acme} --register-account -m admin@${domain} --server letsencrypt >/dev/null 2>&1 || true`);
    const phasesC = ['正在连接证书签发机构...', '正在验证域名所有权（80 端口）...', '正在签发证书...'];
    console.log('  ⏳ 证书申请中（' + domain + ' 的 80 端口需可公网访问，最长约 90 秒）');
    const proc = require('child_process').spawn('bash', ['-c', `${acme} --issue --server letsencrypt -d ${domain} --webroot /var/www/dsh-public --force 2>&1`]);
    let outStr = '';
    let phase = 0;
    const iv = setInterval(() => {
      phase = Math.min(phase + 1, phasesC.length - 1);
      process.stdout.write('\r\u001b[K  ⏳ ' + phasesC[phase] + '   ');
    }, 5000);
    proc.stdout.on('data', d => outStr += d.toString());
    proc.stderr.on('data', d => outStr += d.toString());
    // 修复3：90 秒超时，卡死则杀进程转自签兜底（不再无限等）
    const done = new Promise(res => proc.on('close', () => { clearInterval(iv); process.stdout.write('\r\u001b[K'); res(); }));
    const to = new Promise(res => setTimeout(() => { try { proc.kill('SIGKILL'); } catch (e) {} res(); }, 90000));
    await Promise.race([done, to]);
    if (outStr.includes('Your cert is in')) console.log('  [✓] 证书签发命令已完成');
    else if (outStr.trim()) console.log('  … 证书输出: ' + outStr.split('\n').filter(l => /error|fail|denied|invalid/i.test(l)).slice(0, 3).join(' | ').slice(0, 300));
    const cer = sh(`find /root/.acme.sh/${domain}_ecc -name fullchain.cer 2>/dev/null | head -1`) || sh(`find ~/.acme.sh/${domain}_ecc -name fullchain.cer 2>/dev/null | head -1`);
    const key = sh(`find /root/.acme.sh/${domain}_ecc -name '*.key' 2>/dev/null | grep privkey | head -1`) || sh(`find ~/.acme.sh/${domain}_ecc -name '*.key' 2>/dev/null | grep privkey | head -1`);
    if (cer && key) { sh(`cp ${cer} ${certDir}/${domain}.pem && cp ${key} ${certDir}/${domain}.key`); certOk = true; }
  }
  if (!certOk) {
    sh(`openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout ${certDir}/${domain}.key -out ${certDir}/${domain}.pem -subj '/CN=${domain}' 2>/dev/null`);
    console.log('  [⚠] 已用自签证书（正式使用请确保 acme.sh 能签发）');
  }
  if (certOk) console.log('  [✓] HTTPS 证书申请成功');
  sh('chmod 644 ' + certDir + '/' + domain + '.pem; chmod 600 ' + certDir + '/' + domain + '.key');

  // ── 4/5 停临时隧道 + 加载反代 ──
  step(4, '启用 HTTPS 反代（停用临时隧道）...');
  sh('systemctl stop dsh-tunnel 2>/dev/null');
  sh('nginx -t 2>&1 | tail -1');
  sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null');
  cfg.mode = 'domain'; cfg.domain = domain; cfg.publicUrl = 'https://' + domain;
  saveCfg(cfg);
  console.log('  [✓] HTTPS 反代已启用');

  // ── 5/5 验证 ──
  step(5, '验证公网可达性...');
  let reach = '';
  for (let i = 0; i < 6; i++) {
    try { const r = execSync(`curl -s -k -m 10 -o /dev/null -w "%{http_code}" https://${domain}/__dp/login`, { timeout: 15000 }).toString().trim(); if (r === '200') { reach = 'HTTP ' + r; break; } reach = 'HTTP ' + r; } catch (e) { reach = '等待生效中'; }
    await sleepM(5000);
  }
  console.log('  [' + (reach === 'HTTP 200' ? '✓' : '⚠') + '] ' + (reach === 'HTTP 200' ? '验证完成（' + reach + '）' : '暂未响应（' + reach + '，可稍后 dsh-public status 查看）'));

  console.log('');
  console.log('  ' + '='.repeat(54));
  console.log('   ✅ DSH 已绑定域名！');
  console.log('');
  console.log('   ➜  外网地址（浏览器打开即用）:');
  console.log('       ' + 'https://' + domain);
  console.log('');
  console.log('   首次访问: 页面显示二维码，手机验证器扫码绑定后输入 6 位动态码');
  console.log('   TOTP 绑定不受域名影响，之前绑定过则直接输动态码');
  console.log('  ' + '='.repeat(54));
}

function cmdTunnel() {
  const cfg = loadCfg();
  if (!cfg.user) return console.error('✗ 请先运行 dsh public start');
  sh('systemctl restart dsh-tunnel');
  sh('sleep 8');
  const url = getTunnelUrl();
  if (url) { cfg.publicUrl = url; cfg.mode = 'tunnel'; saveCfg(cfg); log('临时域名: ' + url + ' ｜ 账号: ' + cfg.user + ' / ' + cfg.password); }
  else { log('✗ 临时域名未就绪（看 ' + TUNNEL_LOG + '）'); }
}

function cmdStatus() {
  const cfg = loadCfg();
  if (!cfg.user) return console.log('未开启。运行: dsh public start');
  console.log('公网地址: ' + (cfg.publicUrl || '-'));
  console.log('模式: ' + (cfg.mode === 'domain' ? '自有域名 ' + cfg.domain : 'CF 临时域名'));
  console.log("认证: TOTP 手机验证器（" + (fs.existsSync(DIR + '/auth.json') && JSON.parse(fs.readFileSync(DIR + '/auth.json', 'utf-8')).bound ? '已绑定 ✅' : '未绑定 ⚠ 首次访问页面扫码绑定') + "）");
  console.log('服务: dsh=' + (svcActive('dsh') ? '✅' : '❌') + ' dsh-proxy=' + (svcActive('dsh-proxy') ? '✅' : '❌') + ' dsh-tunnel=' + (svcActive('dsh-tunnel') ? '✅' : '❌'));
  try { const r = sh('curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:' + DSH_PORT + '/'); console.log('DSH 本地: HTTP ' + r); } catch (e) { console.log('DSH 本地: 未响应'); }
  if (cfg.publicUrl) {
    try { const r = sh(`curl -s -k -m 10 -o /dev/null -w "%{http_code}" ${cfg.publicUrl}/__dp/login`); console.log('公网访问(认证页): HTTP ' + r); } catch (e) { console.log('公网访问: 未响应'); }
  }
}

function cmdStop() {
  const cfg = loadCfg();
  sh('systemctl stop dsh-tunnel dsh-proxy');
  sh('pkill -f "[c]loudflared tunnel" 2>/dev/null');
  console.log('已停止公网访问（DSH 保留本地 127.0.0.1:' + DSH_PORT + ' 访问）');
  if (cfg.mode === 'domain') { sh('rm -f /etc/nginx/sites-enabled/dsh-public.conf /etc/nginx/conf.d/dsh-public.conf; systemctl reload nginx 2>/dev/null'); }
}

function cmdAuthReset() {
  // 重置 TOTP 绑定：删除 auth.json + 重启代理 → 下次访问重新扫码绑定
  sh('rm -f ' + DIR + '/auth.json');
  sh('systemctl restart dsh-proxy');
  console.log('✅ 认证已重置');
  console.log('   下次浏览器打开公网地址会重新显示「绑定二维码」，扫码重新绑定即可');
  console.log('   （绑定一次后二维码不再出现，防止他人抢绑）');
}

const cmd = process.argv[2];
switch (cmd) {
  case 'start': cmdStart(process.argv.slice(3)); break;
  case 'auth-reset': cmdAuthReset(); break;
  case 'bind': cmdBind(process.argv.slice(3)); break;
  case 'tunnel': cmdTunnel(); break;
  case 'status': cmdStatus(); break;
  case 'stop': cmdStop(); break;
  default:
    console.log(`dsh-public v3 — DSH 公网访问插件
用法:
  dsh-public start [--password xxx]     一键开启（临时域名）
  dsh-public bind --domain x.com        绑定永久域名
  dsh-public tunnel                     重取临时域名（失效时）
  dsh-public auth-reset                 重置 TOTP 绑定（重新扫码）
  dsh-public status                     状态
  dsh-public stop                       停止
架构: cloudflared → 认证代理 → DSH(仅本地)，全 systemd 断线自愈`);
}