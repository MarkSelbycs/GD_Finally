#!/bin/sh
# 动态取配置后登录：
#   - 从门户 index.cgi 获取 ticket/auth/state 服务器（ServerIPs）
#   - 可选：从门户 URL 提取会话参数（wlanacip/wlanacname/clientmac/paip/vlan/...）
# 用法:
#   sh dynamic.sh
#   sh dynamic.sh 'http://<portal>/qs/index_gz.jsp?wlanacip=..&wlanuserip=..'
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

[ -x ./portal_login ] || { echo "未找到 ./portal_login，请先执行: sh build.sh" >&2; exit 1; }
[ -f ./protect.so ] || { echo "缺少 ./protect.so" >&2; exit 1; }
[ -f ./zxmAlogic.zxm ] || { echo "缺少 ./zxmAlogic.zxm" >&2; exit 1; }
[ -f ./conf/conf.xml ] || { echo "缺少 ./conf/conf.xml" >&2; exit 1; }

portal_url="${1:-${GD_PORTAL_URL:-}}"

# GD_CONFIG_URL 可覆盖门户配置地址（默认由 conf.xml 的 <redirect> 主机推导）
exec env GD_DEBUG="${GD_DEBUG:-1}" GD_PORTAL_URL="$portal_url" \
    ./portal_login --dynamic ./protect.so
