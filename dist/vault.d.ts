import { Level, Secret, AccessToken, AuditLog } from './types';
export declare class Vault {
    private db;
    private encryptionKey;
    constructor(dbPath: string);
    private initSchema;
    isInitialized(): boolean;
    init(masterPassword: string): string;
    unlock(masterPassword: string): boolean;
    lock(): void;
    isUnlocked(): boolean;
    private wrapKey;
    private unwrapKey;
    private encrypt;
    private decrypt;
    createToken(name: string, level: Level): string;
    verifyToken(rawToken: string): {
        token: AccessToken | null;
        valid: boolean;
    };
    listTokens(): AccessToken[];
    deleteToken(name: string): boolean;
    setSecret(name: string, value: string, level: Level, project?: string, category?: string, tags?: string[]): Secret;
    getSecretRaw(name: string, project?: string): Secret | null;
    /** 获取变量引用（脱敏，Agent 看不到明文） */
    getSecretRef(name: string, project?: string): {
        ref: string;
        hint: string;
        level: number;
    } | null;
    /** 获取明文 */
    getSecretReveal(name: string, project?: string): string | null;
    deleteSecret(name: string, project?: string): boolean;
    listSecrets(project?: string, level?: Level): any[];
    searchSecrets(query: string): any[];
    audit(action: AuditLog['action'], secretName: string, secretLevel: Level, tokenName: string, tokenLevel: Level, metadata?: string): void;
    getAuditLogs(limit?: number): AuditLog[];
    /** 替换字符串中的 $VERYKEY:xxx$ 变量，并校验权限 */
    resolveVariables(text: string, tokenName: string, tokenLevel: Level): string;
    close(): void;
}
