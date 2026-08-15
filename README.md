# WCracking

WPS **Pixie Dust** 离线破解工具 —— 用于对 **本人拥有或已获书面授权的无线网络** 进行安全审计，
检测路由器 WPS 实现的随机数熵缺陷，帮助你决定是否需要禁用 WPS / 升级 WPA3 / 更换设备。

> ⚠️ **法律与授权声明（使用前必读）**
>
> 本工具仅限用于 **你本人拥有** 或 **已获得明确书面授权** 的无线网络进行安全测试。
> 未经授权对他人 Wi-Fi 网络实施扫描、破解或接入，在绝大多数国家和地区均属违法，
> 可能构成《刑法》第 285 条「非法侵入计算机信息系统」等罪行。
>
> 本项目（及所依赖的 pixiewps / OneShot / reaver 等开源项目）仅用于教育与授权渗透测试，
> 使用者须自行承担一切法律后果。作者不承担任何因滥用造成的责任。

---

## 这是什么

WPS（Wi-Fi Protected Setup）本意是简化设备接入，但其 PIN 交换实现存在严重缺陷：

- **传统在线 PIN 暴力**：需在线尝试约 11000 种组合，易触发路由器锁 PIN。
- **Pixie Dust（2014，Dominique Bongard）**：部分路由器芯片（Ralink / Realtek / MediaTek /
  Broadcom 早期型号）在 WPS 四次握手中用于生成随机数 E-S1/E-S2 的 PRNG 熵过低甚至固定，
  攻击者可在 **本地离线** 枚举种子恢复 E-S1/E-S2，再用 E-Hash1/E-Hash2 校验暴力还原 8 位 PIN。

本工具是 **pixiewps** 的纯 Python 忠实移植（仅依赖标准库），并整合 OneShot 的安卓端主动攻击流程。

## 支持的攻击方法

| 方法 | 说明 | 依赖 | 速度 |
|------|------|------|------|
| **Pixie Dust（本工具核心）** | 离线还原 PIN，无视密钥位数 | M1-M7 握手数据 | 秒级~分钟级 |
| 在线 PIN 暴力 | 逐位尝试 PIN（含校验位约 11000 种） | 网卡 + reaver/OneShot | 数小时，易锁 PIN |
| 默认 PIN 猜测 | 厂商出厂 PIN（如 12345670） | 无 | 秒级 |
| WPS PBC | 按下路由器 WPS 按钮连接 | 无（需物理接触） | 秒级 |
| 空 PIN（Null PIN） | 部分 AP 空 PIN 可过 | OneShot | 秒级 |

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                         WCracking                            │
├──────────────────────┬──────────────────────────────────────┤
│  PC（Windows/Linux） │  安卓（需 root）                      │
│                      │                                      │
│  core/pixie_dust.py  │  OneShot (wpa_supplicant)  ← 主动攻击 │
│  · 离线 PIN 还原     │  · 抓取 M1-M7 / 计算 AuthKey          │
│  · 5 种 PRNG 模式    │  · 在线 PIN 暴力 / 默认 PIN / 空 PIN  │
│  desktop/app.py GUI  │  · 用还原的 PIN 向 AP 换取 WPA-PSK    │
└──────────────────────┴──────────────────────────────────────┘
```

**关键结论**：WPS Pixie Dust 的「抓包 + M1-M7 交换」步骤在 **Windows 上无法原生完成**
（Windows 驱动不支持监听模式/注入）。真正的主动攻击端在：

1. **安卓手机（root）**：通过 OneShot + wpa_supplicant 直接完成 WPS 交换（无需监听模式）。
2. **Linux（Kali 等）+ USB 无线网卡（监听模式）**：reaver/bully + pixiewps。

Windows 版负责 **离线破解引擎 + 控制器 GUI**：接收握手数据（PKe/PKr/Hash1/Hash2/AuthKey/Nonce），
离线还原 PIN；或接收从安卓/Linux 端回传的数据。

## 目录结构

```
WCracking/
├── core/
│   ├── pixie_dust.py      # 离线 Pixie Dust 引擎（纯 Python，stdlib，已通过公开向量验证）
│   ├── aes.py             # 纯 Python AES-128-CBC（NIST 向量验证）
│   ├── m7_psk.py          # M7 加密设置解密 → 恢复 WPA-PSK（RTL 设备）
│   └── parser.py          # OneShot/reaver 输出解析器
├── engine/                # Rust 加速引擎（ECOS_SIMPLE 等暴力模式多线程，快数十倍）
│   └── src/{main,crypto,prng,crack}.rs
├── desktop/
│   └── app.py             # PyQt6 桌面 GUI（含一键解析填充）
├── android/
│   ├── README.md          # 安卓端完整方案（OneShot + Termux + root + Shizuku 调研）
│   ├── install.sh         # Termux 一键安装脚本
│   └── app/               # 原生安卓 APK 骨架（Kotlin 壳 + 内置 OneShot + libsu）
├── linux/                 # Kali/树莓派支持（reaver/bully + 监听模式网卡）
│   ├── install.sh
│   ├── attack.sh
│   └── README.md
├── tests/
│   └── test_pixie_dust.py # 单元测试（含真实测试向量）
├── docs/
│   └── attack-flow.md     # 攻击流程详解
├── .github/workflows/     # CI：Windows exe / Rust 引擎 / Termux 工具包 / 原生 APK
└── requirements.txt
```

## 快速开始（PC 离线引擎，命令行）

```bash
python -m core.pixie_dust \
  --pke <192字节hex> --pkr <192字节hex> \
  --e-hash1 <32字节hex> --e-hash2 <32字节hex> \
  --authkey <32字节hex> --e-nonce <16字节hex>
```

这些参数由 reaver / OneShot 抓取 WPS 握手后提供（OneShot 会自动打印 `pixiewps` 命令）。

运行测试：

```bash
python tests/test_pixie_dust.py
```

## 快速开始（PC 桌面 GUI）

```bash
pip install -r requirements.txt
python desktop/app.py
```

在界面填入握手数据 → 点「开始破解」→ 查看还原的 PIN / 模式 / 用时。

## 快速开始（安卓端，最推荐的实际攻击路径）

安卓端使用 **OneShot**（Python + wpa_supplicant + pixiewps），需要 **root**（Magisk/KernelSU + Termux）：

```bash
# 在 Termux 中：
pkg install -y root-repo git tsu python wpa-supplicant pixiewps iw openssl
git clone --depth 1 https://github.com/drygdryg/OneShot   # 或本仓库 android/ 附带的脚本
tsudo python OneShot/oneshot.py -i wlan0 -K               # -K = Pixie Dust
```

详见 [`android/README.md`](android/README.md)。

## Rust 加速引擎

ECOS_SIMPLE（2^25 暴力）等模式在纯 Python 下较慢，提供 Rust 加速版（多线程，快数十倍），
已与 Python 引擎逐值交叉验证（含公开测试向量，PIN=04847533）。

**自动快速路径**：Python 引擎 / 桌面 GUI 会检测 `wcracking-engine` 二进制，存在则自动走
Rust 快速路径，失败/缺失时回退纯 Python——无需手动切换。

```bash
cd engine && cargo build --release && cargo test --release
./target/release/wcracking-engine \
  -e <pke> -r <pkr> -s <h1> -z <h2> -a <authkey> -n <nonce> [--mode N] [-f]
```

## Linux 端（Kali / 树莓派）

最可靠的主动攻击平台（USB 网卡监听模式 + reaver/bully），一键脚本：

```bash
bash linux/install.sh          # 装 aircrack-ng/reaver/bully/pixiewps
bash linux/attack.sh wlan0             # 扫描 WPS 网络
bash linux/attack.sh wlan0 <BSSID>     # 指定目标 Pixie Dust 攻击
```

详见 [`linux/README.md`](linux/README.md)。

## 硬件要求

| 平台 | 要求 |
|------|------|
| 安卓 | root（Magisk/KernelSU）+ Termux；MediaTek 机型可能需 `--mtk-wifi` |
| Linux | 支持监听模式的 USB 无线网卡（Atheros/Ralink/Realtek 芯片） |
| Windows | 仅作离线引擎/控制器；如需主动攻击请用安卓或 Linux |

## 构建（GitHub Actions）

推送 `v*` 标签即自动构建并发布 Release（prerelease）：

| Workflow | 产物 |
|----------|------|
| `build-windows.yml` | `WCracking.exe`（PyQt6 GUI，PyInstaller 单文件） |
| `build-rust.yml` | `wcracking-engine`（Windows/Linux 加速引擎） |
| `build-android.yml` | `WCracking-termux.zip`（Termux 工具包） |
| `build-apk.yml` | `WCracking.apk`（原生 APK，实验性） |

本地无 C 编译器时，直接推 tag 触发 Actions 即可。

## 安全建议（防御方）

1. **仅使用 WPA3 加密协议**（WPA2 及以下才可能触发 Pixie Dust；混合模式 WPA2/WPA3 也会触发）。
2. **在路由器后台彻底关闭 WPS**（部分小米/Redmi 旧款默认开启且无法关闭——此时建议更换设备）。
3. 小米 AX3000 之后的设备疑似已修复该漏洞，建议升级/更换。

## 致谢与许可证

- [pixiewps](https://github.com/wiire-a/pixiewps)（GPL-3.0）—— Pixie Dust 攻击原算法，本项目的移植来源。
- [OneShot](https://github.com/drygdryg/OneShot)（GPL-2.0）—— 安卓/Linux 无监听模式 WPS 攻击。
- [reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x)（GPL-2.0）—— 在线 WPS 暴力。
- Pixie Dust 攻击由 Dominique Bongard 于 2014 年发现。

本项目基于 pixiewps 派生，遵循 **GPL-3.0** 许可证。详见 [LICENSE](LICENSE)。
