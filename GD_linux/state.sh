#!/bin/sh
# 查询当前在线状态（state.cgi）
# 用法: sh state.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

[ -x ./portal_login ] || { echo "未找到 ./portal_login，请先执行: sh build.sh" >&2; exit 1; }
[ -f ./protect.so ] || { echo "缺少 ./protect.so" >&2; exit 1; }
[ -f ./zxmAlogic.zxm ] || { echo "缺少 ./zxmAlogic.zxm" >&2; exit 1; }
[ -f ./conf/conf.xml ] || { echo "缺少 ./conf/conf.xml" >&2; exit 1; }

exec env GD_DEBUG="${GD_DEBUG:-1}" ./portal_login --state ./protect.so
