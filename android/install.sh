#!/data/data/com.termux/files/usr/bin/bash
# WCracking 安卓端（Termux）一键安装脚本
# 仅限对本人拥有或已获书面授权的网络进行安全审计。

set -e

echo "[*] WCracking 安卓端安装（Termux + root）"
echo "[*] 请确认你已 root 且理解授权边界。"
echo

pkg update -y
pkg upgrade -y

echo "[*] 安装依赖……"
pkg install -y root-repo git tsu python wpa-supplicant pixiewps iw openssl

echo "[*] 拉取 OneShot……"
if [ -d "$HOME/OneShot" ]; then
    echo "    OneShot 已存在，跳过。"
else
    git clone --depth 1 https://github.com/drygdryg/OneShot "$HOME/OneShot"
fi

echo
echo "[+] 安装完成。使用方式："
echo "    tsudo python ~/OneShot/oneshot.py -i wlan0 -K"
echo
echo "    指定 BSSID："
echo "    tsudo python ~/OneShot/oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K"
echo
echo "    在线 PIN 暴力："
echo "    tsudo python ~/OneShot/oneshot.py -i wlan0 -b <BSSID> -B -p 1234"
echo
echo "⚠️  仅限本人拥有或已获书面授权的网络。"
