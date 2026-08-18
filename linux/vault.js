#!/usr/bin/env node
/**
 * VeryKey vault — AES-256-GCM 加密密钥存储（零依赖）
 * - vault.enc  : salt(16) + iv(12) + authTag(16) + ciphertext(JSON)
 * - master.key : 派生的 32 字节 AES key（base64, 0600 权限）
 * 备份 = master.key + vault.enc 两个文件一起拷贝
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = process.env.VERYKEY_DIR || path.join(os.homedir(), '.verykey');
const VAULT_FILE = path.join(DIR, 'vault.enc');
const MASTER_FILE = path.join(DIR, 'master.key');
const AUDIT_FILE = path.join(DIR, 'audit.log');

function ensureDir() { fs.mkdirSync(DIR, { recursive: true }); }

// ─── Master key ────────────────────────────────
function loadMasterKey() {
  try { return Buffer.from(fs.readFileSync(MASTER_FILE, 'utf-8').trim(), 'base64'); }
  catch (e) { throw new Error('未初始化：请先运行 verykey init'); }
}
function initMasterKey() {
  ensureDir();
  const key = crypto.randomBytes(32);
  fs.writeFileSync(MASTER_FILE, key.toString('base64'), { mode: 0o600 });
  try { fs.chmodSync(MASTER_FILE, 0o600); } catch (e) {}
  return key;
}

// ─── Vault 读写 ────────────────────────────────
function encrypt(key, obj) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plain = Buffer.from(JSON.stringify(obj), 'utf-8');
  const enc = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), enc]);
}
function decrypt(key, data) {
  const salt = data.subarray(0, 16);
  const iv = data.subarray(16, 28);
  const tag = data.subarray(28, 44);
  const enc = data.subarray(44);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  try { return JSON.parse(Buffer.concat([d.update(enc), d.final()]).toString('utf-8')); }
  catch (e) { throw new Error('vault 解密失败（master.key 与 vault.enc 不匹配或文件损坏）'); }
}

function loadVault() {
  try {
    const key = loadMasterKey();
    const data = fs.readFileSync(VAULT_FILE);
    return decrypt(key, data);
  } catch (e) {
    if (e.message.includes('未初始化')) throw e;
    if (e.code === 'ENOENT') return {};
    throw e;
  }
}
function saveVault(obj) {
  ensureDir();
  const key = loadMasterKey();
  fs.writeFileSync(VAULT_FILE, encrypt(key, obj), { mode: 0o600 });
  try { fs.chmodSync(VAULT_FILE, 0o600); } catch (e) {}
}

// ─── 审计 ──────────────────────────────────────
function audit(action, name, by) {
  try {
    ensureDir();
    const line = `${new Date().toISOString()}  ${action}  ${name || '-'}  ${by || 'cli'}\n`;
    fs.appendFileSync(AUDIT_FILE, line, { mode: 0o600 });
  } catch (e) {}
}
function readAudit(n = 50) {
  try {
    const lines = fs.readFileSync(AUDIT_FILE, 'utf-8').trim().split('\n').filter(Boolean);
    return lines.slice(-n).reverse();
  } catch (e) { return []; }
}

// ─── API ───────────────────────────────────────
function mask(v) {
  if (!v) return '';
  const s = String(v);
  if (s.length <= 8) return '****';
  return s.slice(0, 4) + '****' + s.slice(-4);
}

module.exports = {
  DIR, VAULT_FILE, MASTER_FILE, AUDIT_FILE,
  initMasterKey, loadMasterKey,
  loadVault, saveVault, audit, readAudit, mask,
};