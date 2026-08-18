"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// VeryKey - 入口
const cli_1 = require("./cli");
(0, cli_1.runCli)().catch((e) => { console.error('Fatal:', e.message); process.exit(1); });
//# sourceMappingURL=index.js.map