// VeryKey - MCP Server（修复版 + stdio transport）
// AI Agent 通过 MCP 协议调用，默认返回变量引用，Agent 看不到明文
// transport: HTTP (streamable-http 简化版) 或 stdio（供 dsh-mcp-client 等本地 spawn）

import * as http from 'http';
import * as readline from 'readline';
import { Vault } from './vault';
import { Level, LEVEL_NAMES, validateLevel } from './types';

interface McpResponse {
  jsonrpc: '2.0';
  id: number | string | null;
  result?: any;
  error?: { code: number; message: string };
}

/** 创建 MCP 核心处理器（校验 vault/token/master password，返回 handleRequest） */
function createMcp(dbPath: string, rawToken: string): { token: any; handleRequest: (req: any) => McpResponse } {
  const vault = new Vault(dbPath);
  if (!vault.isInitialized()) {
    console.error('❌  Vault not initialized. Run "verykey init" first.');
    process.exit(1);
  }

  const { token: _t, valid } = vault.verifyToken(rawToken);
  if (!valid || !_t) { console.error('❌  Invalid token'); process.exit(1); }
  const token = _t;

  const masterPw = process.env.VERYKEY_MASTER_PASSWORD;
  if (!masterPw) { console.error('❌  VERYKEY_MASTER_PASSWORD env required'); process.exit(1); }
  if (!vault.unlock(masterPw)) { console.error('❌  Wrong master password'); process.exit(1); }

  // MCP 工具定义
  const tools = [
    {
      name: 'verykey_get',
      description: '获取密钥的变量引用（脱敏，Agent 看不到明文值）',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: '密钥名称' },
          project: { type: 'string', description: '所属项目（可选）' },
        },
        required: ['name'],
      },
    },
    {
      name: 'verykey_reveal',
      description: '获取密钥明文（需要高权限 token，操作会记录审计日志）',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          project: { type: 'string' },
        },
        required: ['name'],
      },
    },
    {
      name: 'verykey_list',
      description: '列出当前 token 权限范围内可访问的密钥',
      inputSchema: {
        type: 'object',
        properties: {
          project: { type: 'string', description: '按项目过滤' },
          level: { type: 'number', description: '按权限等级过滤' },
        },
      },
    },
    {
      name: 'verykey_search',
      description: '搜索密钥（仅返回当前 token 权限范围内的结果）',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string' },
        },
        required: ['query'],
      },
    },
    {
      name: 'verykey_set',
      description: '存储密钥',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: '密钥名称' },
          value: { type: 'string', description: '密钥值' },
          project: { type: 'string', description: '所属项目（可选）' },
          level: { type: 'number', description: '权限等级 0-3，默认 1' },
          category: { type: 'string', description: '分类（可选）' },
        },
        required: ['name', 'value'],
      },
    },
    {
      name: 'verykey_resolve',
      description: '解析文本中的 $VERYKEY:xxx$ 变量引用为明文',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string', description: '包含 $VERYKEY:xxx$ 变量的文本' },
        },
        required: ['text'],
      },
    },
  ];

  function handleToolCall(name: string, args: any): any {
    switch (name) {
      case 'verykey_get': {
        const { name: secretName, project = '' } = args;
        const ref = vault.getSecretRef(secretName, project);
        if (!ref) return { error: { code: -32602, message: 'Secret not found' } };

        if (token.level < ref.level) {
          return { error: { code: -32001, message: `Permission denied: need L${ref.level}, have L${token.level}` } };
        }
        vault.audit('read', secretName, ref.level, token.name, token.level);
        return { result: { content: [{ type: 'text', text: ref.ref }], hint: ref.hint, level: ref.level } };
      }

      case 'verykey_reveal': {
        const { name: secretName, project = '' } = args;
        const secret = vault.getSecretRaw(secretName, project);
        if (!secret) return { error: { code: -32602, message: 'Secret not found' } };
        if (token.level < secret.level) {
          return { error: { code: -32001, message: `Permission denied: need L${secret.level}, have L${token.level}` } };
        }
        const plain = vault.getSecretReveal(secretName, project);
        vault.audit('reveal', secretName, secret.level, token.name, token.level);
        return { result: { content: [{ type: 'text', text: plain }] } };
      }

      case 'verykey_list': {
        const filterLevel = args?.level !== undefined ? parseInt(args.level) : undefined;
        let secrets = vault.listSecrets(args?.project, filterLevel);
        // 过滤权限：token 只能看到自己级别及以下的密钥
        secrets = secrets.filter((s: any) => token.level >= s.level);
        return {
          result: {
            content: [{
              type: 'text',
              text: JSON.stringify(secrets.map((s: any) => ({
                name: s.name, project: s.project, level: s.level,
                hint: s.hint, category: s.category,
              })), null, 2),
            }],
          },
        };
      }

      case 'verykey_search': {
        const secrets = vault.searchSecrets(args?.query || '');
        // 过滤权限
        const filtered = secrets.filter((s: any) => token.level >= s.level);
        return {
          result: {
            content: [{
              type: 'text',
              text: JSON.stringify(filtered.map((s: any) => ({
                name: s.name, project: s.project, level: s.level, hint: s.hint,
              })), null, 2),
            }],
          },
        };
      }

      case 'verykey_set': {
        const { name: secretName, value, project = '', level: lvl = 1, category = '' } = args;
        const level = parseInt(lvl);
        if (!validateLevel(level)) {
          return { error: { code: -32602, message: 'Level must be 0-3' } };
        }
        vault.setSecret(secretName, value, level, project, category);
        vault.audit('create', secretName, level, token.name, token.level);
        return { result: { content: [{ type: 'text', text: `✅ ${project ? project + '/' : ''}${secretName} stored (L${level})` }] } };
      }

      case 'verykey_resolve': {
        const text = args?.text || '';
        try {
          const resolved = vault.resolveVariables(text, token.name, token.level);
          return { result: { content: [{ type: 'text', text: resolved }] } };
        } catch (e: any) {
          return { error: { code: -32000, message: e.message } };
        }
      }

      default:
        return { error: { code: -32602, message: `Tool not found: ${name}` } };
    }
  }

  /** 处理单个 MCP JSON-RPC 请求（HTTP 与 stdio 共用） */
  function handleRequest(mcpReq: any): McpResponse {
    const id = mcpReq.id !== undefined ? mcpReq.id : null;
    let response: McpResponse;

    switch (mcpReq.method) {
      case 'initialize':
        response = {
          jsonrpc: '2.0', id,
          result: {
            protocolVersion: '2025-03-26',
            capabilities: { tools: {} },
            serverInfo: { name: 'verykey', version: '0.1.0-rc.7' },
          },
        };
        break;

      case 'tools/list':
        response = { jsonrpc: '2.0', id, result: { tools } };
        break;

      case 'tools/call': {
        const { name, arguments: args } = mcpReq.params || {};
        if (!name) {
          response = { jsonrpc: '2.0', id, error: { code: -32602, message: 'Tool name required' } };
          break;
        }
        const result = handleToolCall(name, args || {});
        response = { jsonrpc: '2.0', id, ...result };
        break;
      }

      default:
        response = { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown method: ${mcpReq.method}` } };
    }

    return response;
  }

  return { token, handleRequest };
}

/** HTTP transport（POST /mcp，JSON-RPC） */
export async function startMcpServer(dbPath: string, rawToken: string, port: number) {
  const { token, handleRequest } = createMcp(dbPath, rawToken);

  console.log(`🔑  VeryKey MCP Server`);
  console.log(`   Token: ${token.name} (L${token.level} - ${LEVEL_NAMES[token.level]})`);
  console.log(`   DB:    ${dbPath}`);
  console.log(`   Port:  ${port}`);

  // HTTP Server
  const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    if (req.method !== 'POST') { res.writeHead(405); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const mcpReq = JSON.parse(body);
        const response = handleRequest(mcpReq);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch (e: any) {
        res.writeHead(400);
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
      }
    });
  });

  server.listen(port, () => {
    console.log(`\n🚀  VeryKey MCP Server running on :${port}`);
    console.log(`   MCP:    http://localhost:${port}/mcp`);
    console.log(`   Token:  ${token.name} (L${token.level})`);
    console.log(`\n   Agent 配置:`);
    console.log(`   {\n     "mcpServers": {\n       "verykey": {\n         "url": "http://localhost:${port}/mcp",\n         "headers": { "Authorization": "Bearer ${rawToken.slice(0, 12)}...${rawToken.slice(-4)}" }\n       }\n     }\n   }`);
  });
}

/** stdio transport：逐行 JSON-RPC over stdin/stdout（供 dsh-mcp-client stdio 方式本地 spawn） */
export function startMcpStdio(dbPath: string, rawToken: string) {
  const { token, handleRequest } = createMcp(dbPath, rawToken);
  console.error(`🔑  VeryKey MCP Server (stdio)`);
  console.error(`   Token: ${token.name} (L${token.level} - ${LEVEL_NAMES[token.level]})`);
  console.error(`   DB:    ${dbPath}`);

  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      const req = JSON.parse(line);
      const res = handleRequest(req);
      process.stdout.write(JSON.stringify(res) + '\n');
    } catch (e: any) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
    }
  });

  rl.on('close', () => { process.exit(0); });
}