// VeryKey - 类型定义

/** 权限等级 */
export enum Level {
  Temp = 0,
  Normal = 1,
  Important = 2,
  Critical = 3,
}

export const LEVEL_NAMES = ['Temp', 'Normal', 'Important', 'Critical'];

/** 密钥条目 */
export interface Secret {
  id: string;
  name: string;
  project: string;
  valueEncrypted: Buffer;
  nonce: Buffer;
  authTag: Buffer;
  level: Level;
  hint: string;
  category: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

/** 访问令牌 */
export interface AccessToken {
  id: string;
  name: string;
  tokenHash: string;
  level: Level;
  lastUsedAt: string | null;
  createdAt: string;
}

/** 审计日志 */
export interface AuditLog {
  id: number;
  action: 'read' | 'reveal' | 'create' | 'update' | 'delete';
  secretName: string;
  secretLevel: Level;
  tokenName: string;
  tokenLevel: Level;
  timestamp: string;
  metadata: string;
}

/** 变量引用格式 */
export const VAR_PREFIX = '$VERYKEY:';
export const VAR_SUFFIX = '$';

/** Token 前缀映射 */
export const LEVEL_PREFIX: Record<Level, string> = {
  [Level.Temp]: 'vk_temp_',
  [Level.Normal]: 'vk_norm_',
  [Level.Important]: 'vk_imp_',
  [Level.Critical]: 'vk_crit_',
};

/** 脱敏显示 */
export function maskValue(value: string): string {
  const len = value.length;
  if (len <= 3) return '***';
  if (len <= 6) return value[0] + '***' + value[len - 1];
  if (len <= 12) return value.slice(0, 2) + '****' + value.slice(-2);
  if (len <= 20) return value.slice(0, 4) + '****' + value.slice(-4);
  return value.slice(0, 6) + '****' + value.slice(-6);
}

/** 校验权限等级 */
export function validateLevel(level: number): level is Level {
  return Number.isInteger(level) && level >= 0 && level <= 3;
}