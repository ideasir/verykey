// VeryKey - HTTP 代理模式
// 自动替换请求体中的 $VERYKEY:xxx$ 变量，Agent 全程看不到明文密钥

import * as http from 'http';
import * as url from 'url';
import { Vault } from './vault';
import { Level, LEVEL_NAMES } from './types';

export async function startProxyServer(dbPath: string, rawToken: string, port: number, targetUrl?: string) {
  const vault = new Vault(dbPath);
  if (!vault.isInitialized()) { console.log('❌  Vault not initialized'); process.exit(1); }

  const { token: _t, valid } = vault.verifyToken(rawToken); if (!valid || !_t) { console.log("❌  Invalid token"); process.exit(1); } const token = _t;
  if (!valid) { console.log('❌  Invalid token'); process.exit(1); }

  const masterPw = process.env.VERYKEY_MASTER_PASSWORD;
  if (!masterPw) { console.log('❌  VERYKEY_MASTER_PASSWORD env required'); process.exit(1); }
  if (!vault.unlock(masterPw)) { console.log('❌  Wrong master password'); process.exit(1); }

  console.log(`🔑  VeryKey Proxy Server`);
  console.log(`   Token: ${token.name} (L${token.level} - ${LEVEL_NAMES[token.level]})`);
  console.log(`   Port:  ${port}`);
  if (targetUrl) console.log(`   Target: ${targetUrl}`);

  const server = http.createServer(async (clientReq, clientRes) => {
    try {
      // 收集请求体
      const chunks: Buffer[] = [];
      for await (const chunk of clientReq) { chunks.push(chunk); }
      let body = Buffer.concat(chunks).toString('utf8');

      // 替换变量引用
      if (body && body.includes('$VERYKEY:')) {
        try {
          body = vault.resolveVariables(body, token.name, token.level);
        } catch (e: any) {
          console.error(`[PROXY] Variable resolution failed: ${e.message}`);
          clientRes.writeHead(400, { 'Content-Type': 'application/json' });
          clientRes.end(JSON.stringify({ error: `Variable resolution failed: ${e.message}` }));
          return;
        }
      }

      if (targetUrl) {
        await forwardToTarget(clientReq, body, clientRes, targetUrl);
      } else {
        // 无目标服务器时，直接返回替换结果（用于测试/调试）
        clientRes.writeHead(200, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ resolved: true, body, token: token.name }));
      }
    } catch (e: any) {
      console.error(`[PROXY] Error: ${e.message}`);
      if (!clientRes.headersSent) {
        clientRes.writeHead(500, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ error: e.message }));
      }
    }
  });

  server.listen(port, () => {
    console.log(`\n🚀  VeryKey Proxy running on :${port}`);
    console.log(`   Agent 配置: 所有请求通过此代理转发`);
    console.log(`   请求体中的 $VERYKEY:xxx$ 被自动替换为真实密钥`);
    console.log(`   Agent 全程看不到明文密钥`);
  });
}

async function forwardToTarget(
  clientReq: http.IncomingMessage,
  body: string,
  clientRes: http.ServerResponse,
  targetUrl: string,
) {
  try {
    const target = new url.URL(targetUrl);
    const path = clientReq.url || '/';

    const options = {
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path,
      method: clientReq.method,
      headers: { ...clientReq.headers, 'Content-Length': Buffer.byteLength(body).toString(), host: target.hostname },
    };

    const proxyReq = http.request(options, (proxyRes) => {
      clientRes.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(clientRes);
    });

    proxyReq.on('error', (e) => {
      console.error(`[PROXY] Forward error: ${e.message}`);
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ error: `Bad gateway: ${e.message}` }));
    });

    proxyReq.write(body);
    proxyReq.end();
  } catch (e: any) {
    clientRes.writeHead(500, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ error: `Invalid target URL: ${e.message}` }));
  }
}