#!/bin/bash
# dsh-public 一键安装（root）：支持 本地文件(同目录) 或 在线(管道 wget|bash) 两种方式
echo "════════════════════════════════════"
echo "  dsh-public — DSH 公网访问插件 安装"
echo "════════════════════════════════════"

# 1. 检查 root
if [ "$(id -u)" != "0" ]; then echo "✗ 请用 root 运行: sudo bash install.sh"; exit 1; fi

# 2. 检查 node
if ! command -v node >/dev/null 2>&1; then
  echo "✗ 未找到 Node.js（dsh 需要 Node 20+）"; exit 1
fi

# 3. 放置文件（本地或在线）
mkdir -p /opt/dsh-public
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
ok=1

if [ -f "$SCRIPT_DIR/cli.js" ] && [ -f "$SCRIPT_DIR/proxy.js" ]; then
  echo "✓ 从本地目录复制插件文件..."
  cp "$SCRIPT_DIR/cli.js" "$SCRIPT_DIR/proxy.js" /opt/dsh-public/
  [ -f "$SCRIPT_DIR/qrcode.min.js" ] && cp "$SCRIPT_DIR/qrcode.min.js" /opt/dsh-public/
elif [ -n "$BASH_EXECUTION_STRING" ] || [ -p /dev/stdin ]; then
  echo "… 在线下载插件文件（管道安装模式）..."
  BASE="ideasir/verykey/main/dsh-public"
  for f in cli.js proxy.js qrcode.min.js; do
    got=0
    for URL in \
      "https://gh-proxy.com/https://raw.githubusercontent.com/$BASE/$f" \
      "https://raw.githubusercontent.com/$BASE/$f" \
      "https://cdn.jsdelivr.net/gh/ideasir/verykey@main/dsh-public/$f"; do
      if curl -sL -m 60 -o "/opt/dsh-public/$f" "$URL" 2>/dev/null && node --check "/opt/dsh-public/$f" >/dev/null 2>&1; then
        got=1; echo "  ✓ $f 下载完成"; break
      fi
    done
    [ "$got" = "0" ] && { echo "✗ $f 下载失败（检查网络或手动拷贝）"; ok=0; }
  done
else
  echo "✗ 缺少 cli.js/proxy.js——请把 install.sh/cli.js/proxy.js 放同一目录，或用:wget -qO- ...install.sh | bash"; exit 1
fi

[ "$ok" = "0" ] && exit 1
chmod +x /opt/dsh-public/*.js
# 创建 `dsh-public` 命令（等同 cli.js）
ln -sf /opt/dsh-public/cli.js /usr/local/bin/dsh-public
chmod +x /usr/local/bin/dsh-public
echo "✓ 插件文件 → /opt/dsh-public/（命令: dsh-public）"

# 4. cloudflared（ARM/AMD 自动）
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "… 安装 cloudflared..."
  ARCH=$(uname -m)
  BIN=$([ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] && echo cloudflared-linux-arm64 || echo cloudflared-linux-amd64)
  for URL in \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/$BIN" \
    "https://gh-proxy.com/https://github.com/cloudflare/cloudflared/releases/latest/download/$BIN"; do
    if curl -sL -m 120 -o /tmp/cloudflared "$URL" && chmod +x /tmp/cloudflared && mv /tmp/cloudflared /usr/local/bin/cloudflared; then
      echo "✓ cloudflared 安装完成"; break
    fi
  done
  command -v cloudflared >/dev/null 2>&1 || echo "⚠️ cloudflared 安装失败（可手动安装后重试）"
fi

echo ""
echo "✅ 安装完成！开启公网访问："
echo "   sudo dsh-public start"
echo "   绑定永久域名：sudo dsh-public bind --domain 你的域名"
echo "   查看状态：sudo dsh-public status"