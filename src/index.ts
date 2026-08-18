// VeryKey - 入口
import { runCli } from './cli';
runCli().catch((e) => { console.error('Fatal:', e.message); process.exit(1); });