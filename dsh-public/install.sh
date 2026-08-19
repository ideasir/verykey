#!/bin/bash
# dsh-public 一键安装（root）：装 cloudflared + 放置插件文件
set -e
echo "════════════════════════════════════"
echo "  dsh-public — DSH 公网访问插件 安装"
echo "════════════════════════════════════"

# 1. 检查 root
if [ "$(id -u)" != "0" ]; then echo "✗ 请用 root 运行: sudo bash install.sh"; exit 1; fi

# 2. 检查 node
if ! command -v node >/dev/null 2>&1; then
  echo "✗ 未找到 Node.js（dsh 需要 Node 20+）"; exit 1
fi

# 3. 放置文件
mkdir -p /opt/dsh-public
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/cli.js" "$SCRIPT_DIR/proxy.js" /opt/dsh-public/ 2>/dev/null || {
  echo "✗ 请把 install.sh / cli.js / proxy.js 放在同一目录"; exit 1;
}
chmod +x /opt/dsh-public/*.js
echo "✓ 插件文件 → /opt/dsh-public/"

# 4. cloudflared（ARM/AMD 自动）
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "… 安装 cloudflared..."
  ARCH=$(uname -m)
  BIN=$([ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] && echo cloudflared-linux-arm64 || echo cloudflared-linux-amd64)
  for URL in \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/$BIN" \
    "https://gh-proxy.com/https://github.com/cloudflare/cloudflared/releases/latest/download/$BIN"; do
    if curl -sL -m 120 -o /tmp/cloudflared "$URL" && chmod +x /tmp/cloudflared && mv /tmp/cloudflared /usr/local/bin/cloudflared; then
      break
    fi
  done
  command -v cloudflared >/dev/null 2>&1 && echo "✓ cloudflared 安装完成" || echo "⚠️ cloudflared 安装失败（可手动安装后重试）"
fi

echo ""
echo "✅ 安装完成！开启公网访问："
echo "   sudo dsh public start"
echo "   绑定永久域名：sudo dsh public bind --domain 你的域名"
echo "   查看状态：sudo dsh public status"