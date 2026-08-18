#!/usr/bin/env node
/**
 * VeryKey CLI — 密钥托管 + 包装命令执行
 *
 *   verykey init                      # 初始化（生成 master key + 空 vault）
 *   verykey add NAME [VALUE]          # 存/更新密钥（不给 VALUE 则隐藏输入）
 *   verykey list                      # 脱敏列表
 *   verykey get NAME                  # 明文输出（仅脚本管道用）
 *   verykey rm NAME                   # 删除
 *   verykey run NAME... -- CMD ARGS   # 解析密钥注入子进程环境执行（值不外泄）
 *   verykey audit [N]                 # 审计记录
 */
'use strict';
const { spawnSync } = require('child_process');
const readline = require('readline');
const V = require('./vault.js');

function hideInput(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode && stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    let buf = '';
    const onData = (c) => {
      if (c === '\u0003') { process.exit(130); }
      if (c === '\r' || c === '\n') {
        stdin.setRawMode && stdin.setRawMode(false);
        process.stdout.write('\n');
        rl.close();
        resolve(buf);
        return;
      }
      if (c === '\u007f' || c === '\b') { buf = buf.slice(0, -1); return; }
      buf += c;
    };
    stdin.on('data', onData);
  });
}

const args = process.argv.slice(2);
const cmd = args[0];

function fail(msg) { console.error('✗ ' + msg); process.exit(1); }

(async () => {
  switch (cmd) {
    case 'init': {
      V.initMasterKey();
      V.saveVault({});
      V.audit('init', '-', 'cli');
      console.log('✓ VeryKey 已初始化');
      console.log(`  数据目录: ${V.DIR}`);
      console.log(`  备份 = 拷贝 ${'master.key'} 和 ${'vault.enc'} 两个文件`);
      break;
    }

    case 'add': {
      const name = args[1];
      if (!name) fail('用法: verykey add NAME [VALUE]');
      if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(name)) fail('变量名需为 UPPER_SNAKE_CASE（如 GITHUB_TOKEN）');
      let value = args[2];
      if (value === undefined) value = await hideInput(`输入 ${name} 的值（隐藏输入）: `);
      if (!value) fail('值不能为空');
      const vault = V.loadVault();
      vault[name] = { value, note: (vault[name] && vault[name].note) || '', createdAt: (vault[name] && vault[name].createdAt) || new Date().toISOString(), updatedAt: new Date().toISOString() };
      V.saveVault(vault);
      V.audit('add/update', name, 'cli');
      console.log(`✓ ${name} 已保存`);
      break;
    }

    case 'list': {
      const vault = V.loadVault();
      const names = Object.keys(vault).sort();
      if (!names.length) { console.log('(空) 还没有密钥，用 verykey add NAME VALUE 添加'); break; }
      console.log('名称'.padEnd(28) + '值(脱敏)'.padEnd(22) + '更新时间');
      for (const n of names) {
        const e = vault[n];
        console.log(n.padEnd(28) + V.mask(e.value).padEnd(22) + (e.updatedAt || '').slice(0, 19));
      }
      break;
    }

    case 'get': {
      const name = args[1];
      if (!name) fail('用法: verykey get NAME');
      const vault = V.loadVault();
      if (!vault[name]) fail(`未找到 ${name}`);
      process.stdout.write(vault[name].value + '\n');
      V.audit('get', name, 'cli');
      break;
    }

    case 'rm': {
      const name = args[1];
      if (!name) fail('用法: verykey rm NAME');
      const vault = V.loadVault();
      if (!vault[name]) fail(`未找到 ${name}`);
      delete vault[name];
      V.saveVault(vault);
      V.audit('delete', name, 'cli');
      console.log(`✓ ${name} 已删除`);
      break;
    }

    case 'run': {
      // verykey run NAME... -- CMD ARGS
      const dash = args.indexOf('--');
      if (dash < 0 || dash === args.length - 1) fail('用法: verykey run NAME... -- CMD ARGS');
      const names = args.slice(1, dash);
      const cmdline = args.slice(dash + 1);
      if (!names.length) fail('至少指定一个变量名');
      const vault = V.loadVault();
      const env = { ...process.env };
      for (const n of names) {
        if (!vault[n]) fail(`未找到密钥 ${n}`);
        env[n] = vault[n].value;
      }
      V.audit('run(' + names.join(',') + ')', '-', 'cli');
      const r = spawnSync(cmdline[0], cmdline.slice(1), { env, stdio: 'inherit', shell: false });
      process.exit(r.status === null ? 1 : r.status);
      break;
    }

    case 'audit': {
      const n = parseInt(args[1], 10) || 50;
      const lines = V.readAudit(n);
      if (!lines.length) { console.log('(无记录)'); break; }
      for (const l of lines) console.log(l);
      break;
    }

    case 'help':
    case '-h':
    case '--help':
    default:
      console.log(`VeryKey — 密钥托管
用法:
  verykey init                     初始化
  verykey add NAME [VALUE]         保存/更新密钥（隐藏输入）
  verykey list                     脱敏列表
  verykey get NAME                 明文输出（管道用）
  verykey rm NAME                  删除
  verykey run NAME... -- CMD ARGS  注入环境执行命令
  verykey audit [N]                审计
`);
      break;
  }
})().catch((e) => fail(e.message));