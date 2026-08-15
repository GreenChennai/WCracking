#!/usr/bin/env bash
# WCracking Linux 依赖安装脚本（Kali / Debian / Ubuntu / 树莓派 OS）
# 仅限对本人拥有或已获书面授权的网络进行安全审计。
set -e

echo "[*] WCracking Linux 依赖安装"
echo "[*] 检测发行版……"

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    # aircrack-ng（含 airmon-ng/wash）、reaver、pixiewps、bully、iw、无线工具
    sudo apt-get install -y aircrack-ng iw wireless-tools || true
    sudo apt-get install -y reaver bully pixiewps || true
    # 若 reaver/bully/pixiewps 不在仓库（非 Kali），从源码编译
    for pkg in reaver bully pixiewps; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo "[!] $pkg 不在仓库，需手动编译（见 linux/README.md）"
        fi
    done
elif command -v pacman >/dev/null 2>&1; then
    # Arch 系
    sudo pacman -Sy --noconfirm aircrack-ng reaver bully pixiewps iw
else
    echo "[x] 未识别的包管理器，请手动安装：aircrack-ng reaver bully pixiewps iw"
    exit 1
fi

echo
echo "[+] 依赖安装完成。验证："
for c in airmon-ng wash reaver bully pixiewps iw; do
    if command -v $c >/dev/null 2>&1; then
        echo "    ✓ $c ($($c --version 2>/dev/null | head -1 || echo ok))"
    else
        echo "    ✗ $c 未安装"
    fi
done

echo
echo "下一步：bash linux/attack.sh <wlan0> [<BSSID>]"
echo "⚠️  仅限本人拥有或已获书面授权的网络。"
