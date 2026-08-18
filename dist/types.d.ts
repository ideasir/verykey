/** 权限等级 */
export declare enum Level {
    Temp = 0,
    Normal = 1,
    Important = 2,
    Critical = 3
}
export declare const LEVEL_NAMES: string[];
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
export declare const VAR_PREFIX = "$VERYKEY:";
export declare const VAR_SUFFIX = "$";
/** Token 前缀映射 */
export declare const LEVEL_PREFIX: Record<Level, string>;
/** 脱敏显示 */
export declare function maskValue(value: string): string;
/** 校验权限等级 */
export declare function validateLevel(level: number): level is Level;
