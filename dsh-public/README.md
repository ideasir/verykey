# dsh-public — DSH 公网访问插件

装好即用：一条命令让 DSH 通过公网访问（临时域名秒级可用，也可绑定永久域名）。

> **安全设计**：DSH 本身只允许监听 127.0.0.1（反 RCE 暴露），本插件通过「公网隧道 → 认证代理 → DSH」实现公网访问，DSH 始终保持本地监听 + 密码认证前置。

## 架构

```
公网浏览器 → https://xxx.trycloudflare.com（临时域名，CF 自动 HTTPS）
              ↓ cloudflared 隧道（systemd 断线自愈）
             认证代理 127.0.0.1:9443（账号密码 + Host 改写）
              ↓
             DSH 127.0.0.1:3080（仅本地监听，trusted-host 放行 /api）
```

## 安装

```bash
# 一条命令（root/普通用户均可，加 sudo）
wget -qO- https://gh-proxy.com/https://raw.githubusercontent.com/ideasir/verykey/main/dsh-public/install.sh | sudo bash
```
自动：下载部署插件文件 + 创建 `dsh-public` 命令 + 安装 cloudflared（GitHub 多源）。

## 使用

```bash
# 一键开启（临时域名，10 秒内可用）
sudo dsh-public start
# → 输出: https://xxx.trycloudflare.com + 账号(admin) + 自动生成密码

# 指定密码
sudo dsh-public start --password 你的密码

# 绑定永久域名（需该域名 DNS 解析到本机公网 IP）
sudo dsh-public bind --domain dsh.example.com
# → https://dsh.example.com（acme.sh 自动证书；无 acme 则自签）

# 临时域名失效后重取
sudo dsh-public tunnel

# 状态 / 停止
sudo dsh-public status
sudo dsh-public stop   # 停公网；DSH 本地 127.0.0.1:3080 保持可用
```

## 卸载

```bash
sudo dsh-public stop
sudo rm -f /etc/systemd/system/dsh-tunnel.service /etc/systemd/system/dsh-proxy.service
sudo systemctl daemon-reload
sudo rm -rf /opt/dsh-public /usr/local/bin/dsh-public
# DSH 本体不受影响（本地 127.0.0.1:3080 继续可用）
```

## 说明

- 三个 systemd 服务（dsh / dsh-proxy / dsh-tunnel）全部自动重启，崩溃/断线自愈
- 临时域名（trycloudflare）免费、无需账号，但**域名随机、可能随时失效**——失效就跑 `sudo dsh-public tunnel`，或绑定永久域名一劳永逸
- 绑定了永久域名后临时隧道自动休眠；需要临时用可再 `dsh-public tunnel`
- 浏览器首次访问输入账号密码（`admin` + 密码）即可，功能与本地完全一致

## 文件

| 文件 | 作用 |
|------|------|
| `cli.js` | 主程序（start/bind/tunnel/status/stop）|
| `proxy.js` | 认证代理（账号密码 + Host 改写转发）|
| `install.sh` | 一键安装（cloudflared + 文件部署 + dsh-public 命令）|