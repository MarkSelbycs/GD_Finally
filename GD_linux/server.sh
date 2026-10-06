#!/bin/sh
# 启动命名管道服务（IPC server）
# 使用 run/clientpipe、run/serverpipe 两个 FIFO
# 用法: sh server.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

[ -x ./portal_login ] || { echo "未找到 ./portal_login，请先执行: sh build.sh" >&2; exit 1; }
[ -f ./protect.so ] || { echo "缺少 ./protect.so" >&2; exit 1; }

mkdir -p "$here/run"
echo "命名管道目录: $here/run"
exec env GD_DEBUG="${GD_DEBUG:-1}" GD_PIPE_DIR="$here/run" \
    ./portal_login --server ./protect.so
