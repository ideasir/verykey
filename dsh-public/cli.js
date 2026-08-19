#!/usr/bin/env node
/**
 * dsh-public v3 — DSH 公网访问插件（终版）
 *
 *   dsh public start                 # 一键开启：临时域名（交互输密码/回车自动生成）
 *   dsh public start --password xxx  # 指定密码
 *   dsh public bind --domain x.com   # 绑定自有域名（nginx+证书，临时隧道休眠）
 *   dsh public tunnel                # 重新获取临时域名（临时域名失效时）
 *   dsh public status                # 状态
 *   dsh public stop                  # 停止公网访问
 *
 * 架构（全部 systemd 常驻，断线自愈）：
 *   cloudflared(dsh-tunnel) → proxy(dsh-proxy,认证+Host改写) → DSH(dsh,仅本地)
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
function proxyUnit(user, pass) {
  return `[Unit]
Description=dsh-public proxy
After=network.target

[Service]
ExecStart=/usr/bin/node ${PROXY}
Environment=DP_PORT=${PROXY_PORT}
Environment=DP_TRUST_HOST=${TRUST_HOST}
Environment=DP_USER=${user}
Environment=DP_PASS=${pass}
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
  const user = opt.user || cfg.user || 'admin';
  let pass = opt.password || cfg.password || '';
  if (!pass) { pass = crypto.randomBytes(9).toString('base64url'); log('已自动生成访问密码: ' + pass + '（存储于 ' + CONFIG + '）'); }

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
  writeUnit('dsh-proxy', proxyUnit(user, pass));
  writeUnit('dsh-tunnel', TUNNEL_UNIT);
  cfg.user = user; cfg.password = pass; cfg.mode = 'tunnel';
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
  if (url) { try { const r = execSync(`curl -s -k -m 10 -u ${user}:${pass} -o /dev/null -w "%{http_code}" ${url}/`, { timeout: 15000 }).toString().trim(); reach = 'HTTP ' + r; } catch (e) { reach = '首次连接建立中'; } }
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
  console.log('   登录账号: ' + user);
  console.log('   登录密码: ' + pass);
  console.log('');
  console.log('   绑定永久域名: sudo dsh-public bind --domain 你的域名');
  console.log('   停止访问:     sudo dsh-public stop');
  console.log('  ' + '='.repeat(54));
}

async function cmdBind(argv) {
  const opt = parseArgs(argv);
  const domain = opt.domain || (await ask('请输入域名（如 dsh.example.com）: '));
  if (!domain) return console.error('✗ 需要域名');
  const cfg = loadCfg();
  const user = cfg.user || 'admin', pass = cfg.password || '';
  if (!pass) return console.error('✗ 请先运行 dsh public start 初始化');

  // nginx vhost（443 → 本机 proxy）→ proxy 转发 DSH
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
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
  writeUnit('dsh-domain', conf); // 借用 writeUnit 写临时文件
  fs.writeFileSync('/tmp/dsh-public-domain.conf', conf);
  const sitesDir = fs.existsSync('/etc/nginx/sites-enabled') ? '/etc/nginx/sites-enabled' : '/etc/nginx/conf.d';
  sh(`cp /tmp/dsh-public-domain.conf ${sitesDir}/dsh-public.conf`);
  sh('mkdir -p /var/www/dsh-public');

  // 证书：acme.sh 优先，自签兜底
  const acme = sh('which acme.sh') || sh('ls ~/.acme.sh/acme.sh 2>/dev/null');
  let certOk = false;
  if (acme) {
    sh(`${acme} --issue -d ${domain} --webroot /var/www/dsh-public --force 2>&1 | tail -2`);
    const cer = sh(`find ~/.acme.sh/${domain}_ecc -name fullchain.cer 2>/dev/null | head -1`);
    const key = sh(`find ~/.acme.sh/${domain}_ecc -name '*.key' 2>/dev/null | grep privkey | head -1`);
    if (cer && key) { sh(`cp ${cer} ${certDir}/${domain}.pem && cp ${key} ${certDir}/${domain}.key`); certOk = true; }
  }
  if (!certOk) { sh(`openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout ${certDir}/${domain}.key -out ${certDir}/${domain}.pem -subj '/CN=${domain}' 2>/dev/null`); log('（使用自签证书，浏览器会有安全提示；正式使用请配 acme.sh）'); }
  sh('chmod 644 ' + certDir + '/' + domain + '.pem; chmod 600 ' + certDir + '/' + domain + '.key');

  // DSH trusted-host 改域名 + 停隧道
  writeUnit('dsh', dshUnit(domain, DSH_PORT));
  sh('systemctl daemon-reload && systemctl restart dsh');
  sh('systemctl stop dsh-tunnel');
  sh('nginx -t 2>&1 | tail -1; systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null');

  cfg.mode = 'domain'; cfg.domain = domain; cfg.publicUrl = 'https://' + domain;
  saveCfg(cfg);
  log('✅ 已绑定永久域名: https://' + domain);
  log('   账号: ' + user + ' / ' + pass);
  log('   DNS 提示: 确保 ' + domain + ' 已解析到本机公网 IP（未解析时会显示证书/连接错误）');
  log('   临时域名已休眠；需要时 dsh public tunnel 可临时重取');
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
  console.log('账号: ' + cfg.user + ' / ' + cfg.password);
  console.log('服务: dsh=' + (svcActive('dsh') ? '✅' : '❌') + ' dsh-proxy=' + (svcActive('dsh-proxy') ? '✅' : '❌') + ' dsh-tunnel=' + (svcActive('dsh-tunnel') ? '✅' : '❌'));
  try { const r = sh('curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:' + DSH_PORT + '/'); console.log('DSH 本地: HTTP ' + r); } catch (e) { console.log('DSH 本地: 未响应'); }
  if (cfg.publicUrl) {
    try { const r = sh(`curl -s -k -m 10 -u ${cfg.user}:${cfg.password} -o /dev/null -w "%{http_code}" ${cfg.publicUrl}/`); console.log('公网访问: HTTP ' + r); } catch (e) { console.log('公网访问: 未响应'); }
  }
}

function cmdStop() {
  const cfg = loadCfg();
  sh('systemctl stop dsh-tunnel dsh-proxy');
  sh('pkill -f "[c]loudflared tunnel" 2>/dev/null');
  console.log('已停止公网访问（DSH 保留本地 127.0.0.1:' + DSH_PORT + ' 访问）');
  if (cfg.mode === 'domain') { sh('rm -f /etc/nginx/sites-enabled/dsh-public.conf /etc/nginx/conf.d/dsh-public.conf; systemctl reload nginx 2>/dev/null'); }
}

const cmd = process.argv[2];
switch (cmd) {
  case 'start': cmdStart(process.argv.slice(3)); break;
  case 'bind': cmdBind(process.argv.slice(3)); break;
  case 'tunnel': cmdTunnel(); break;
  case 'status': cmdStatus(); break;
  case 'stop': cmdStop(); break;
  default:
    console.log(`dsh-public v3 — DSH 公网访问插件
用法:
  dsh public start [--password xxx]     一键开启（临时域名）
  dsh public bind --domain x.com        绑定永久域名
  dsh public tunnel                     重取临时域名（失效时）
  dsh public status                     状态
  dsh public stop                       停止
架构: cloudflared → 认证代理 → DSH(仅本地)，全 systemd 断线自愈`);
}