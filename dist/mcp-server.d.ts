/** HTTP transport（POST /mcp，JSON-RPC） */
export declare function startMcpServer(dbPath: string, rawToken: string, port: number): Promise<void>;
/** stdio transport：逐行 JSON-RPC over stdin/stdout（供 dsh-mcp-client stdio 方式本地 spawn） */
export declare function startMcpStdio(dbPath: string, rawToken: string): void;
