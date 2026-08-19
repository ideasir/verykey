#!/usr/bin/env node
/**
 * dsh-public 反代：认证 + 转发 → 127.0.0.1:3080（保留 Host 头供 DSH trusted-host 放行 /api）
 * 本地明文 HTTP：公网 TLS 由 cloudflared(临时域名)/nginx(自有域名)承担
 * 零依赖。环境变量：DP_PORT / DP_USER / DP_PASS
 */
'use strict';
const http = require('http');
const fs = require('fs');

const PORT = parseInt(process.env.DP_PORT || '9443', 10);
const UP_HOST = process.env.DP_UP_HOST || '127.0.0.1';
const UP_PORT = parseInt(process.env.DP_UP_PORT || '3080', 10);
const USER = process.env.DP_USER || 'admin';
const PASS = process.env.DP_PASS || '';
const LOG = process.env.DP_LOG || '/tmp/dsh-public-proxy.log';

function log(m) { try { fs.appendFileSync(LOG, `[${new Date().toISOString()}] ${m}\n`); } catch (e) {} }

const expected = 'Basic ' + Buffer.from(USER + ':' + PASS).toString('base64');

http.createServer((req, res) => {
  if ((req.headers.authorization || '') !== expected) {
    log(`401 ${req.method} ${req.url} (from ${req.socket.remoteAddress})`);
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="dsh-public"', 'Content-Type': 'text/plain' });
    res.end('dsh-public: authentication required');
    return;
  }
  // Host 统一改写为 TRUST_HOST（DSH --trusted-host 固定匹配，不依赖通配符）
  const TRUST_HOST = process.env.DP_TRUST_HOST || 'dsh.local';
  const headers = Object.assign({}, req.headers, { host: TRUST_HOST });
  const up = http.request({ host: UP_HOST, port: UP_PORT, path: req.url, method: req.method, headers }, (ur) => {
    res.writeHead(ur.statusCode, ur.headers);
    ur.pipe(res);
  });
  up.on('error', (e) => { log(`upstream error: ${e.message}`); res.writeHead(502); res.end('bad gateway'); });
  req.pipe(up);
}).listen(PORT, '127.0.0.1', () => {
  log(`listening http://127.0.0.1:${PORT} -> ${UP_HOST}:${UP_PORT}`);
  console.log(`dsh-public proxy: http://127.0.0.1:${PORT} -> ${UP_HOST}:${UP_PORT}`);
});