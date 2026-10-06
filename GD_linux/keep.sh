#!/bin/sh
# 登录并保活：登录成功后周期性发送 keep.cgi 保持在线
# 用法: sh keep.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

[ -x ./portal_login ] || { echo "未找到 ./portal_login，请先执行: sh build.sh" >&2; exit 1; }
[ -f ./protect.so ] || { echo "缺少 ./protect.so" >&2; exit 1; }
[ -f ./zxmAlogic.zxm ] || { echo "缺少 ./zxmAlogic.zxm" >&2; exit 1; }
[ -f ./conf/conf.xml ] || { echo "缺少 ./conf/conf.xml" >&2; exit 1; }

exec env GD_DEBUG="${GD_DEBUG:-1}" ./portal_login --keep ./protect.so
