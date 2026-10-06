#!/bin/sh
# 构建脚本：编译门户登录程序
# 用法: sh build.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

command -v gcc >/dev/null 2>&1 || {
    echo "缺少 gcc，请先安装：sudo apt install -y build-essential" >&2
    exit 1
}
command -v pkg-config >/dev/null 2>&1 || {
    echo "缺少 pkg-config，请先安装：sudo apt install -y pkg-config" >&2
    exit 1
}
pkg-config --exists libxml-2.0 || {
    echo "缺少 libxml2 开发包，请先安装：sudo apt install -y libxml2-dev" >&2
    exit 1
}

gcc -std=c11 -O2 -Wall -Wextra \
    "$here/src/portal_login.c" \
    -o "$here/portal_login" \
    $(pkg-config --cflags --libs libxml-2.0) -ldl

echo "构建完成: $here/portal_login"
