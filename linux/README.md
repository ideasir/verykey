# VeryKey · Linux 版（零依赖）

轻量密钥托管：加密存储 + TOTP WebUI + 智能体"变量引用"注入。

**核心设计**：智能体只能看到变量名（`GITHUB_TOKEN`），密钥值仅在 `verykey run` 包装命令内部解析、注入到子进程环境——值不进对话上下文、不进日志、智能体无读取通道。

## 组成

| 文件 | 作用 |
|------|------|
| `vault.js` | AES-256-GCM 加密存储（master.key + vault.enc）|
| `cli.js` | CLI：init / add / list(脱敏) / get / rm / run / audit |
| `server.js` | WebUI（TOTP 认证 + 密钥管理 + 审计），监听 127.0.0.1:3081 |
| `qrcode.min.js` | TOTP 绑定二维码库 |

## 部署（Node 20+，无其他依赖）

```bash
mkdir -p /opt/verykey && cd /opt/verykey
# 放入 4 个文件
node cli.js init          # 初始化（生成 master.key + vault.enc 于 ~/.verykey/）
# 常驻 WebUI（systemd）
cat > /etc/systemd/system/verykey.service <<'EOF'
[Unit]
Description=VeryKey WebUI
After=network.target
[Service]
ExecStart=/usr/bin/node /opt/verykey/server.js
Restart=always
RestartSec=2
User=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable verykey && systemctl start verykey
```

## CLI 用法

```bash
verykey add GITHUB_TOKEN            # 保存（隐藏输入）
verykey add OPENAI_API_KEY sk-xxx   # 保存（显式）
verykey list                        # 脱敏列表
verykey run GITHUB_TOKEN -- git push origin main   # 包装注入执行
verykey audit                       # 审计日志
```

## WebUI

- 地址 `http://127.0.0.1:3081`（外部访问走 SSH 隧道）
- 首次访问扫码绑定 TOTP（绑定后二维码永久隐藏）
- 密钥列表**脱敏显示**（`前4****后4`），无查看明文入口

## 安全模型

1. **存储**：vault.enc = AES-256-GCM（salt/iv/tag 随机），master.key 0600 root 专属
2. **WebUI**：TOTP 双重认证 + 无状态签名 session（7 天免登录）
3. **智能体隔离**：无 reveal 接口；值只存在于 `run` 的瞬间子进程环境；审计记录每次使用
4. **备份**：拷贝 `~/.verykey/master.key` + `~/.verykey/vault.enc` 两个文件即可迁移