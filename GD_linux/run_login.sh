#!/bin/sh
# 运行脚本：门户认证登录
# 用法: sh run_login.sh
# 运行后按提示在终端输入账号与密码（密码不回显）。
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

if [ ! -x ./portal_login ]; then
    echo "未找到 ./portal_login，请先执行: sh build.sh" >&2
    exit 1
fi
[ -f ./protect.so ] || { echo "缺少 ./protect.so" >&2; exit 1; }
[ -f ./zxmAlogic.zxm ] || { echo "缺少 ./zxmAlogic.zxm" >&2; exit 1; }
[ -f ./conf/conf.xml ] || { echo "缺少 ./conf/conf.xml" >&2; exit 1; }

# GD_DEBUG=1 输出非敏感诊断（状态、字节数、服务端错误码），可用 GD_DEBUG=0 关闭。
exec env GD_DEBUG="${GD_DEBUG:-1}" ./portal_login ./protect.so
