"use strict";
// VeryKey - HTTP 代理模式
// 自动替换请求体中的 $VERYKEY:xxx$ 变量，Agent 全程看不到明文密钥
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.startProxyServer = startProxyServer;
const http = __importStar(require("http"));
const url = __importStar(require("url"));
const vault_1 = require("./vault");
const types_1 = require("./types");
async function startProxyServer(dbPath, rawToken, port, targetUrl) {
    const vault = new vault_1.Vault(dbPath);
    if (!vault.isInitialized()) {
        console.log('❌  Vault not initialized');
        process.exit(1);
    }
    const { token: _t, valid } = vault.verifyToken(rawToken);
    if (!valid || !_t) {
        console.log("❌  Invalid token");
        process.exit(1);
    }
    const token = _t;
    if (!valid) {
        console.log('❌  Invalid token');
        process.exit(1);
    }
    const masterPw = process.env.VERYKEY_MASTER_PASSWORD;
    if (!masterPw) {
        console.log('❌  VERYKEY_MASTER_PASSWORD env required');
        process.exit(1);
    }
    if (!vault.unlock(masterPw)) {
        console.log('❌  Wrong master password');
        process.exit(1);
    }
    console.log(`🔑  VeryKey Proxy Server`);
    console.log(`   Token: ${token.name} (L${token.level} - ${types_1.LEVEL_NAMES[token.level]})`);
    console.log(`   Port:  ${port}`);
    if (targetUrl)
        console.log(`   Target: ${targetUrl}`);
    const server = http.createServer(async (clientReq, clientRes) => {
        try {
            // 收集请求体
            const chunks = [];
            for await (const chunk of clientReq) {
                chunks.push(chunk);
            }
            let body = Buffer.concat(chunks).toString('utf8');
            // 替换变量引用
            if (body && body.includes('$VERYKEY:')) {
                try {
                    body = vault.resolveVariables(body, token.name, token.level);
                }
                catch (e) {
                    console.error(`[PROXY] Variable resolution failed: ${e.message}`);
                    clientRes.writeHead(400, { 'Content-Type': 'application/json' });
                    clientRes.end(JSON.stringify({ error: `Variable resolution failed: ${e.message}` }));
                    return;
                }
            }
            if (targetUrl) {
                await forwardToTarget(clientReq, body, clientRes, targetUrl);
            }
            else {
                // 无目标服务器时，直接返回替换结果（用于测试/调试）
                clientRes.writeHead(200, { 'Content-Type': 'application/json' });
                clientRes.end(JSON.stringify({ resolved: true, body, token: token.name }));
            }
        }
        catch (e) {
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
async function forwardToTarget(clientReq, body, clientRes, targetUrl) {
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
    }
    catch (e) {
        clientRes.writeHead(500, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ error: `Invalid target URL: ${e.message}` }));
    }
}
//# sourceMappingURL=proxy.js.map