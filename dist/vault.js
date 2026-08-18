"use strict";
// VeryKey - 加密引擎 + SQLite 存储
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Vault = void 0;
const better_sqlite3_1 = __importDefault(require("better-sqlite3"));
const crypto = __importStar(require("crypto"));
const uuid_1 = require("uuid");
const types_1 = require("./types");
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
class Vault {
    db;
    encryptionKey = null;
    constructor(dbPath) {
        this.db = new better_sqlite3_1.default(dbPath);
        this.db.pragma('journal_mode = WAL');
        this.initSchema();
    }
    // ─── Schema ───────────────────────────────────────────────
    initSchema() {
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        project TEXT NOT NULL DEFAULT '',
        value_encrypted BLOB NOT NULL,
        nonce BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        level INTEGER NOT NULL DEFAULT 1,
        hint TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        token_hash TEXT NOT NULL,
        level INTEGER NOT NULL DEFAULT 1,
        last_used_at TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        secret_name TEXT NOT NULL,
        secret_level INTEGER NOT NULL,
        token_name TEXT NOT NULL,
        token_level INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        metadata TEXT NOT NULL DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name, project);
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    `);
    }
    // ─── 初始化 / 解锁 ───────────────────────────────────────
    isInitialized() {
        const row = this.db.prepare("SELECT value FROM meta WHERE key = 'salt'").get();
        return !!row;
    }
    init(masterPassword) {
        if (this.isInitialized())
            throw new Error('Vault already initialized');
        if (!masterPassword || masterPassword.length < 4)
            throw new Error('Master password must be at least 4 characters');
        const salt = crypto.randomBytes(16);
        const key = crypto.randomBytes(KEY_LENGTH);
        const wrapped = this.wrapKey(key, masterPassword, salt);
        // 验证用的主密码 hash
        const verifyHash = crypto.createHash('sha256').update(masterPassword).digest('hex');
        const insert = this.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?)");
        insert.run('salt', salt.toString('hex'));
        insert.run('wrapped_key', wrapped);
        insert.run('verify_hash', verifyHash);
        this.encryptionKey = key;
        return 'Vault initialized';
    }
    unlock(masterPassword) {
        const saltRow = this.db.prepare("SELECT value FROM meta WHERE key = 'salt'").get();
        const wrappedRow = this.db.prepare("SELECT value FROM meta WHERE key = 'wrapped_key'").get();
        const hashRow = this.db.prepare("SELECT value FROM meta WHERE key = 'verify_hash'").get();
        if (!saltRow || !wrappedRow || !hashRow)
            throw new Error('Vault not initialized');
        // 验证主密码
        if (crypto.createHash('sha256').update(masterPassword).digest('hex') !== hashRow.value) {
            return false;
        }
        const salt = Buffer.from(saltRow.value, 'hex');
        this.encryptionKey = this.unwrapKey(wrappedRow.value, masterPassword, salt);
        return true;
    }
    lock() {
        this.encryptionKey = null;
    }
    isUnlocked() {
        return this.encryptionKey !== null;
    }
    // ─── 密钥包装 ───────────────────────────────────────────
    wrapKey(key, password, salt) {
        const kek = crypto.pbkdf2Sync(password, salt, 600000, KEY_LENGTH, 'sha512');
        const cipher = crypto.createCipheriv(ALGORITHM, kek, Buffer.alloc(NONCE_LENGTH, 0));
        const encrypted = Buffer.concat([cipher.update(key), cipher.final()]);
        return Buffer.concat([encrypted, cipher.getAuthTag()]).toString('hex');
    }
    unwrapKey(wrapped, password, salt) {
        const data = Buffer.from(wrapped, 'hex');
        const encrypted = data.subarray(0, data.length - TAG_LENGTH);
        const authTag = data.subarray(data.length - TAG_LENGTH);
        const kek = crypto.pbkdf2Sync(password, salt, 600000, KEY_LENGTH, 'sha512');
        const decipher = crypto.createDecipheriv(ALGORITHM, kek, Buffer.alloc(NONCE_LENGTH, 0));
        decipher.setAuthTag(authTag);
        return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }
    // ─── 单密钥加解密 ───────────────────────────────────────
    encrypt(plaintext) {
        if (!this.encryptionKey)
            throw new Error('Vault is locked');
        const nonce = crypto.randomBytes(NONCE_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, this.encryptionKey, nonce);
        const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        return { encrypted, nonce, tag: cipher.getAuthTag() };
    }
    decrypt(encrypted, nonce, tag) {
        if (!this.encryptionKey)
            throw new Error('Vault is locked');
        const decipher = crypto.createDecipheriv(ALGORITHM, this.encryptionKey, nonce);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
    }
    // ─── Token 管理 ─────────────────────────────────────────
    createToken(name, level) {
        if (!this.encryptionKey)
            throw new Error('Vault is locked');
        if (!name || !name.trim())
            throw new Error('Token name is required');
        if (!(0, types_1.validateLevel)(level))
            throw new Error('Level must be 0-3');
        if (this.db.prepare("SELECT id FROM tokens WHERE name = ?").get(name.trim())) {
            throw new Error(`Token "${name}" already exists`);
        }
        const prefix = types_1.LEVEL_NAMES[level].toLowerCase();
        const raw = `vk_${prefix}_${crypto.randomBytes(24).toString('base64url')}`;
        const hash = crypto.createHash('sha256').update(raw).digest('hex');
        this.db.prepare(`INSERT INTO tokens (id, name, token_hash, level, created_at) VALUES (?, ?, ?, ?, ?)`).run((0, uuid_1.v4)(), name.trim(), hash, level, new Date().toISOString());
        return raw;
    }
    verifyToken(rawToken) {
        const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
        const row = this.db.prepare("SELECT * FROM tokens WHERE token_hash = ?").get(hash);
        if (!row)
            return { token: null, valid: false };
        const token = {
            id: row.id, name: row.name, tokenHash: row.token_hash,
            level: row.level, lastUsedAt: row.last_used_at, createdAt: row.created_at,
        };
        this.db.prepare("UPDATE tokens SET last_used_at = ? WHERE id = ?")
            .run(new Date().toISOString(), row.id);
        return { token, valid: true };
    }
    listTokens() {
        const rows = this.db.prepare("SELECT * FROM tokens ORDER BY level DESC, created_at ASC").all();
        return rows.map(r => ({
            id: r.id, name: r.name, tokenHash: r.token_hash,
            level: r.level, lastUsedAt: r.last_used_at, createdAt: r.created_at,
        }));
    }
    deleteToken(name) {
        return this.db.prepare("DELETE FROM tokens WHERE name = ?").run(name.trim()).changes > 0;
    }
    // ─── 密钥管理 ──────────────────────────────────────────
    setSecret(name, value, level, project = '', category = '', tags = []) {
        if (!this.encryptionKey)
            throw new Error('Vault is locked');
        if (!name || !name.trim())
            throw new Error('Secret name is required');
        if (!(0, types_1.validateLevel)(level))
            throw new Error('Level must be 0-3');
        const { encrypted, nonce, tag } = this.encrypt(value);
        const hint = (0, types_1.maskValue)(value);
        const now = new Date().toISOString();
        const cleanName = name.trim();
        const cleanProject = project.trim();
        const existing = this.db.prepare("SELECT id FROM secrets WHERE name = ? AND project = ?").get(cleanName, cleanProject);
        if (existing) {
            this.db.prepare(`UPDATE secrets SET value_encrypted=?, nonce=?, auth_tag=?, level=?, hint=?, category=?, tags=?, updated_at=?
         WHERE name=? AND project=?`).run(encrypted, nonce, tag, level, hint, category, JSON.stringify(tags), now, cleanName, cleanProject);
        }
        else {
            this.db.prepare(`INSERT INTO secrets (id, name, project, value_encrypted, nonce, auth_tag, level, hint, category, tags, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run((0, uuid_1.v4)(), cleanName, cleanProject, encrypted, nonce, tag, level, hint, category, JSON.stringify(tags), now, now);
        }
        return this.getSecretRaw(cleanName, cleanProject);
    }
    getSecretRaw(name, project = '') {
        const row = this.db.prepare("SELECT * FROM secrets WHERE name = ? AND project = ?").get(name.trim(), project.trim());
        if (!row)
            return null;
        return {
            id: row.id, name: row.name, project: row.project,
            valueEncrypted: row.value_encrypted, nonce: row.nonce, authTag: row.auth_tag,
            level: row.level, hint: row.hint, category: row.category,
            tags: JSON.parse(row.tags || '[]'),
            createdAt: row.created_at, updatedAt: row.updated_at,
        };
    }
    /** 获取变量引用（脱敏，Agent 看不到明文） */
    getSecretRef(name, project = '') {
        const secret = this.getSecretRaw(name, project);
        if (!secret)
            return null;
        const p = project.trim() ? project.trim() + '/' : '';
        const ref = `${types_1.VAR_PREFIX}${p}${name.trim()}${types_1.VAR_SUFFIX}`;
        return { ref, hint: secret.hint, level: secret.level };
    }
    /** 获取明文 */
    getSecretReveal(name, project = '') {
        const secret = this.getSecretRaw(name, project);
        if (!secret)
            return null;
        return this.decrypt(secret.valueEncrypted, secret.nonce, secret.authTag);
    }
    deleteSecret(name, project = '') {
        return this.db.prepare("DELETE FROM secrets WHERE name = ? AND project = ?").run(name.trim(), project.trim()).changes > 0;
    }
    listSecrets(project, level) {
        let query = "SELECT id, name, project, level, hint, category, tags, created_at, updated_at FROM secrets WHERE 1=1";
        const params = [];
        if (project) {
            query += " AND project = ?";
            params.push(project.trim());
        }
        if (level !== undefined) {
            query += " AND level = ?";
            params.push(level);
        }
        query += " ORDER BY level DESC, name ASC";
        return this.db.prepare(query).all(...params).map((r) => ({
            ...r, tags: JSON.parse(r.tags || '[]'),
        }));
    }
    searchSecrets(query) {
        const like = `%${query.trim()}%`;
        return this.db.prepare(`SELECT id, name, project, level, hint, category, tags, created_at, updated_at
       FROM secrets WHERE name LIKE ? OR project LIKE ? OR category LIKE ?
       ORDER BY level DESC, name ASC`).all(like, like, like).map((r) => ({
            ...r, tags: JSON.parse(r.tags || '[]'),
        }));
    }
    // ─── 审计日志 ──────────────────────────────────────────
    audit(action, secretName, secretLevel, tokenName, tokenLevel, metadata = '{}') {
        this.db.prepare(`INSERT INTO audit_log (action, secret_name, secret_level, token_name, token_level, timestamp, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?)`).run(action, secretName, secretLevel, tokenName, tokenLevel, new Date().toISOString(), metadata);
    }
    getAuditLogs(limit = 50) {
        const rows = this.db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?").all(limit);
        return rows.map(r => ({
            id: r.id,
            action: r.action,
            secretName: r.secret_name,
            secretLevel: r.secret_level,
            tokenName: r.token_name,
            tokenLevel: r.token_level,
            timestamp: r.timestamp,
            metadata: r.metadata,
        }));
    }
    // ─── 变量替换 ─────────────────────────────────────────
    /** 替换字符串中的 $VERYKEY:xxx$ 变量，并校验权限 */
    resolveVariables(text, tokenName, tokenLevel) {
        const regex = /\$VERYKEY:([^$]+)\$/g;
        return text.replace(regex, (match, path) => {
            const parts = path.trim().split('/');
            let name, project = '';
            if (parts.length >= 2) {
                project = parts[0];
                name = parts.slice(1).join('/');
            }
            else {
                name = parts[0];
            }
            const secret = this.getSecretRaw(name, project);
            if (!secret)
                throw new Error(`Secret not found: ${match}`);
            if (tokenLevel < secret.level) {
                throw new Error(`Permission denied: ${match} requires level ${secret.level}, token has ${tokenLevel}`);
            }
            const plain = this.decrypt(secret.valueEncrypted, secret.nonce, secret.authTag);
            this.audit('reveal', name, secret.level, tokenName, tokenLevel, JSON.stringify({ mode: 'proxy' }));
            return plain;
        });
    }
    close() {
        this.lock();
        this.db.close();
    }
}
exports.Vault = Vault;
//# sourceMappingURL=vault.js.map