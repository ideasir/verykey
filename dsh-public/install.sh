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

# 4. acme.sh（HTTPS 证书自动签发）
if [ ! -f /root/.acme.sh/acme.sh ]; then
  echo "… 安装 acme.sh（HTTPS 证书工具）..."
  curl -sL https://get.acme.sh | sh -s email=dsh@example.com >/dev/null 2>&1 || \
    curl -sL https://gh-proxy.com/https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s email=dsh@example.com >/dev/null 2>&1
  [ -f /root/.acme.sh/acme.sh ] && echo "✓ acme.sh 安装完成" || echo "⚠️ acme.sh 安装失败（绑定时将使用自签证书）"
fi

echo ""
echo "✅ 安装完成！"
echo "════════════════════════════════════════════"
echo " 📌 最后一步：绑定公网域名（没有域名则无法公网访问）"
echo ""

# 5. 域名参数（支持一条命令直接绑定: ...install.sh | sudo bash -s -- dsh.example.com）
ARG_DOMAIN="${1:-}"

DSH_HTTP=$(curl -s -m 4 -o /dev/null -w "%{http_code}" http://127.0.0.1:3080/ 2>/dev/null || echo 000)
if [ "$DSH_HTTP" != "200" ] && [ "$DSH_HTTP" != "302" ] && [ "$DSH_HTTP" != "404" ]; then
  echo "⚠️  未检测到本地 DSH（127.0.0.1:3080 未响应）"
  if [ -n "$ARG_DOMAIN" ]; then
    echo "   请先启动 DSH，再运行：sudo dsh-public bind --domain $ARG_DOMAIN"
  else
    echo "   请先启动 DSH，再运行：sudo dsh-public bind"
  fi
  echo "   （DSH 本地使用不受影响，当 DSH 运行后随时可绑定域名）"
  exit 0
fi

if [ -n "$ARG_DOMAIN" ]; then
  echo ""
  echo " … 正在全自动绑定 $ARG_DOMAIN（解析验证→nginx→证书→HTTPS）..."
  /usr/local/bin/dsh-public bind --domain "$ARG_DOMAIN"
elif [ -t 0 ]; then
  # 交互模式：引导输入域名
  read -p " 请输入已解析到本机公网 IP 的域名（如 dsh.example.com；直接回车跳过）: " DOMAIN
  if [ -n "$DOMAIN" ]; then
    echo ""
    echo " … 正在全自动绑定 $DOMAIN（解析验证→nginx→证书→HTTPS）..."
    /usr/local/bin/dsh-public bind --domain "$DOMAIN"
  else
    echo ""
    echo " ⚠️  已跳过域名绑定。之后随时执行:"
    echo "     sudo dsh-public bind            # 按提示输入域名（推荐）"
    echo "     sudo dsh-public bind --domain 你的域名"
    echo ""
    echo "     DSH 本地使用不受影响: http://127.0.0.1:3080"
  fi
else
  # 管道安装模式且无参数：提示一条命令带域名
  echo " ⚠️  未提供域名。一条命令安装+绑定："
  echo ""
  echo "     wget -qO- https://gh-proxy.com/https://raw.githubusercontent.com/ideasir/verykey/main/dsh-public/install.sh | sudo bash -s -- 你的域名"
  echo "     # 或装好后执行: sudo dsh-public bind"
  echo ""
  echo "     DSH 本地使用不受影响: http://127.0.0.1:3080"
fi