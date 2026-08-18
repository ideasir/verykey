"use strict";
// VeryKey - CLI 入口（修复版）
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
exports.runCli = runCli;
const commander_1 = require("commander");
const readline = __importStar(require("readline"));
const vault_1 = require("./vault");
const types_1 = require("./types");
const mcp_server_1 = require("./mcp-server");
const proxy_1 = require("./proxy");
const DEFAULT_DB = process.env.VERYKEY_DB || './verykey.db';
function promptHidden(question) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question(question, (pw) => { rl.close(); resolve(pw); });
    });
}
function getMasterPassword() {
    const pw = process.env.VERYKEY_MASTER_PASSWORD;
    if (pw)
        return pw;
    throw new Error('Master password required. Set VERYKEY_MASTER_PASSWORD env or use interactive mode.');
}
async function runCli() {
    const program = new commander_1.Command();
    program
        .name('verykey')
        .description('🔑 VeryKey - 轻量级密钥管理系统')
        .version('1.0.0')
        .option('--db <path>', 'Vault database path', DEFAULT_DB);
    // ─── init ───────────────────────────────────────────────
    program
        .command('init')
        .description('初始化加密数据库')
        .option('--password <pw>', '主密码（不传则交互输入）')
        .action(async (cmdOpts) => {
        const opts = program.opts();
        try {
            const vault = new vault_1.Vault(opts.db);
            if (vault.isInitialized()) {
                console.log('⚠️  Vault already initialized');
                vault.close();
                return;
            }
            const pw = cmdOpts.password || process.env.VERYKEY_MASTER_PASSWORD || await promptHidden('Master password: ');
            if (!pw || pw.length < 4) {
                console.log('❌  Password must be at least 4 characters');
                vault.close();
                return;
            }
            vault.init(pw);
            console.log('✅  Vault initialized');
            console.log('📁  Database:', opts.db);
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    // ─── token ──────────────────────────────────────────────
    const tokenCmd = program.command('token').description('管理访问令牌');
    tokenCmd
        .command('create')
        .description('创建访问令牌')
        .requiredOption('--name <name>', '令牌名称')
        .requiredOption('--level <level>', '权限等级: 0=Temp, 1=Normal, 2=Important, 3=Critical')
        .action(async (cmdOpts) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const level = parseInt(cmdOpts.level);
            if (!(0, types_1.validateLevel)(level)) {
                console.log('❌  Level must be 0-3');
                vault.close();
                return;
            }
            const token = vault.createToken(cmdOpts.name, level);
            console.log(`✅  Token: ${token}`);
            console.log(`   Name:  ${cmdOpts.name}`);
            console.log(`   Level: L${level} (${types_1.LEVEL_NAMES[level]})`);
            console.log('   ⚠️  Save this token - it will not be shown again');
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    tokenCmd
        .command('list')
        .description('列出所有令牌')
        .action(async () => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const tokens = vault.listTokens();
            if (tokens.length === 0) {
                console.log('No tokens');
            }
            else {
                for (const t of tokens) {
                    console.log(`  ${t.name.padEnd(20)} L${t.level} (${types_1.LEVEL_NAMES[t.level]})  last: ${t.lastUsedAt || 'never'}`);
                }
            }
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    tokenCmd
        .command('delete')
        .description('删除令牌')
        .requiredOption('--name <name>', '令牌名称')
        .action(async (cmdOpts) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            if (vault.deleteToken(cmdOpts.name)) {
                console.log(`✅  Token "${cmdOpts.name}" deleted`);
            }
            else {
                console.log(`❌  Token "${cmdOpts.name}" not found`);
            }
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    // ─── set ─────────────────────────────────────────────────
    program
        .command('set')
        .description('存储密钥')
        .argument('<path>', '密钥路径: project/name 或 name')
        .argument('<value>', '密钥值')
        .option('--level <level>', '权限等级: 0-3', '1')
        .option('--category <cat>', '分类', '')
        .option('--tag <tags>', '标签（逗号分隔）', '')
        .action(async (path, value, cmdOpts) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const parts = path.split('/');
            const name = parts.length >= 2 ? parts.slice(1).join('/') : parts[0];
            const project = parts.length >= 2 ? parts[0] : '';
            const level = parseInt(cmdOpts.level);
            const tags = cmdOpts.tag ? cmdOpts.tag.split(',').map((t) => t.trim()).filter(Boolean) : [];
            if (!(0, types_1.validateLevel)(level)) {
                console.log('❌  Level must be 0-3');
                vault.close();
                return;
            }
            vault.setSecret(name, value, level, project, cmdOpts.category, tags);
            console.log(`✅  Stored: ${path} (L${level})`);
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    // ─── get ─────────────────────────────────────────────────
    program
        .command('get')
        .description('读取密钥（默认返回变量引用，--reveal 返回明文）')
        .argument('<path>', '密钥路径: project/name 或 name')
        .option('--reveal', '返回明文', false)
        .action(async (path, cmdOpts) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const parts = path.split('/');
            const name = parts.length >= 2 ? parts.slice(1).join('/') : parts[0];
            const project = parts.length >= 2 ? parts[0] : '';
            if (cmdOpts.reveal) {
                const plain = vault.getSecretReveal(name, project);
                if (plain === null) {
                    console.log('❌  Not found');
                }
                else {
                    console.log(plain);
                }
            }
            else {
                const ref = vault.getSecretRef(name, project);
                if (ref === null) {
                    console.log('❌  Not found');
                }
                else {
                    console.log(`Ref:   ${ref.ref}`);
                    console.log(`Hint:  ${ref.hint}`);
                    console.log(`Level: L${ref.level} (${types_1.LEVEL_NAMES[ref.level]})`);
                }
            }
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    // ─── list ────────────────────────────────────────────────
    program
        .command('list')
        .description('列出密钥')
        .option('--project <project>', '按项目过滤')
        .option('--level <level>', '按等级过滤')
        .action(async (cmdOpts) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const level = cmdOpts.level !== undefined ? parseInt(cmdOpts.level) : undefined;
            if (level !== undefined && !(0, types_1.validateLevel)(level)) {
                console.log('❌  Level must be 0-3');
                vault.close();
                return;
            }
            const secrets = vault.listSecrets(cmdOpts.project, level);
            if (secrets.length === 0) {
                console.log('No secrets');
            }
            else {
                for (const s of secrets) {
                    const path = s.project ? `${s.project}/${s.name}` : s.name;
                    console.log(`  ${path.padEnd(30)} L${s.level} (${types_1.LEVEL_NAMES[s.level]})  ${s.hint}`);
                }
            }
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    // ─── search ──────────────────────────────────────────────
    program
        .command('search')
        .description('搜索密钥')
        .argument('<query>', '搜索关键词')
        .action(async (query) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const secrets = vault.searchSecrets(query);
            if (secrets.length === 0) {
                console.log('No results');
            }
            else {
                for (const s of secrets) {
                    const path = s.project ? `${s.project}/${s.name}` : s.name;
                    console.log(`  ${path.padEnd(30)} L${s.level} (${types_1.LEVEL_NAMES[s.level]})  ${s.hint}`);
                }
            }
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    // ─── mcp-stdio ─────────────────────────────────────────
    program
        .command('mcp-stdio')
        .description('启动 MCP Server（stdio 传输，供 DSH 等本地 spawn）')
        .option('--token <token>', '认证 token')
        .action(async (cmdOpts) => {
        const token = cmdOpts.token || process.env.VERYKEY_TOKEN;
        if (!token) {
            console.log('❌  MCP server requires a token');
            console.log('   Usage: verykey mcp-stdio --token <token>');
            console.log('   Or:    export VERYKEY_TOKEN=... && verykey mcp-stdio');
            return;
        }
        (0, mcp_server_1.startMcpStdio)(program.opts().db, token);
    });
    // ─── mcp ─────────────────────────────────────────────────
    program
        .command('mcp')
        .description('启动 MCP Server（AI Agent 原生调用）')
        .option('--port <port>', '服务端口', '8443')
        .option('--token <token>', '认证 token')
        .action(async (cmdOpts) => {
        const token = cmdOpts.token || process.env.VERYKEY_TOKEN;
        if (!token) {
            console.log('❌  MCP server requires a token');
            console.log('   Usage: verykey mcp --token <token>');
            console.log('   Or:    export VERYKEY_TOKEN=... && verykey mcp');
            return;
        }
        const masterPw = process.env.VERYKEY_MASTER_PASSWORD;
        if (!masterPw) {
            console.log('❌  VERYKEY_MASTER_PASSWORD env required');
            return;
        }
        await (0, mcp_server_1.startMcpServer)(program.opts().db, token, parseInt(cmdOpts.port));
    });
    // ─── proxy ───────────────────────────────────────────────
    program
        .command('proxy')
        .description('启动 HTTP 代理（自动替换 $VERYKEY:xxx$ 变量）')
        .option('--port <port>', '代理端口', '8080')
        .option('--token <token>', '认证 token')
        .option('--target <url>', '目标服务器地址')
        .action(async (cmdOpts) => {
        const token = cmdOpts.token || process.env.VERYKEY_TOKEN;
        if (!token) {
            console.log('❌  Proxy requires --token or VERYKEY_TOKEN env');
            return;
        }
        const masterPw = process.env.VERYKEY_MASTER_PASSWORD;
        if (!masterPw) {
            console.log('❌  VERYKEY_MASTER_PASSWORD env required');
            return;
        }
        await (0, proxy_1.startProxyServer)(program.opts().db, token, parseInt(cmdOpts.port), cmdOpts.target);
    });
    // ─── audit ───────────────────────────────────────────────
    program
        .command('audit')
        .description('查看审计日志')
        .option('--limit <n>', '条数', '20')
        .action(async (cmdOpts) => {
        try {
            const vault = new vault_1.Vault(program.opts().db);
            if (!vault.isInitialized()) {
                console.log('⚠️  Not initialized');
                vault.close();
                return;
            }
            if (!vault.unlock(getMasterPassword())) {
                console.log('❌  Wrong password');
                vault.close();
                return;
            }
            const logs = vault.getAuditLogs(parseInt(cmdOpts.limit));
            if (logs.length === 0) {
                console.log('No audit logs');
            }
            else {
                for (const l of logs) {
                    console.log(`  [${l.timestamp}] ${l.action.padEnd(8)} ${l.secretName} by ${l.tokenName} (L${l.tokenLevel})`);
                }
            }
            vault.close();
        }
        catch (e) {
            console.error('❌', e.message);
        }
    });
    await program.parseAsync(process.argv);
}
//# sourceMappingURL=cli.js.map