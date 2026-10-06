#!/bin/sh
# 通过命名管道向 server.sh 发送请求
# 用法: sh client.sh connect [账号]     # 连接（会提示输入密码）
#       sh client.sh disconnect          # 断开（注销）
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

[ -x ./portal_login ] || { echo "未找到 ./portal_login，请先执行: sh build.sh" >&2; exit 1; }

action="${1:-connect}"
shift || true

exec env GD_DEBUG="${GD_DEBUG:-1}" GD_PIPE_DIR="$here/run" \
    ./portal_login --client "$action" "$@"
