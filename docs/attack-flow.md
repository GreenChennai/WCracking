# Pixie Dust 攻击流程详解

> 本文用于教育目的。仅限对本人拥有或已获书面授权的网络进行安全审计。

## 一、WPS 握手回顾

WPS 注册协议（EAP-WSC）在 Enrollee（AP）与 Registrar（客户端）之间交换 8 条消息：

```
M1  AP → Client : PKe, E-Nonce(N1), ...
M2  Client → AP : PKr, R-Nonce, ...
M3  AP → Client : E-Hash1, E-Hash2, ...     ← PIN 前后两半的 HMAC 校验值
M4-M8 ...        : 完成 PIN 验证、交换加密的网络配置
```

其中：
- `PKe / PKr`：双方 Diffie-Hellman 公钥（1536-bit MODP 群）。
- `E-Hash1 = HMAC-SHA256(AuthKey, E-S1 || PSK1 || PKe || PKr)`，其中 `PSK1 = HMAC(AuthKey, PIN前半)`。
- `E-Hash2 = HMAC-SHA256(AuthKey, E-S2 || PSK2 || PKe || PKr)`，其中 `PSK2 = HMAC(AuthKey, PIN后半)`。
- `E-S1 / E-S2`：AP 内部的「秘密随机数」，正常实现应为强随机。

## 二、漏洞本质

部分芯片（Ralink / Realtek / MediaTek / Broadcom 早期型号）生成 E-S1/E-S2 的 PRNG **熵过低**：

| 芯片 | PRNG | 弱点 | pixiewps 模式 |
|------|------|------|--------------|
| Ralink / MTK / Cameo | 32-bit LFSR | 可从 nonce 反推 | 1 (RT/MT/CL) |
| Broadcom (eCos) | 线性同余 LCG | 熵仅 25 位 | 2 (eCos simple) |
| Realtek RTL819x | glibc random | 时间戳种子 | 3 (RTL819x) |
| eCos 最简 | LCG | 2^32 暴力 | 4 (eCos simplest) |
| eCos Knuth | Park-Miller | 2^32 暴力 | 5 (eCos Knuth) |

## 三、攻击流程

```
1. 抓取 M1-M3
   ├─ 安卓：OneShot（root + wpa_supplicant，无需监听模式）
   └─ Linux：reaver/bully（监听模式网卡）

2. 计算/获取 AuthKey
   ├─ 通常由 OneShot/reaver 打印（改版 reaver 输出 --authkey）
   └─ 或由 E-Nonce + R-Nonce + BSSID 推导（RTL/小 DH 密钥场景）

3. 离线恢复 E-S1/E-S2
   └─ 枚举 PRNG 种子，使生成的字节流匹配 E-Nonce，从而重构 E-S1/E-S2

4. 离线还原 PIN
   ├─ 前半：0000..9999（10000 种），用 E-Hash1 校验
   └─ 后半：000..999 + 校验位（约 1000 种），用 E-Hash2 校验

5. 获取 WPA-PSK
   ├─ 用 PIN 重新发起 WPS 注册 → AP 返回加密的网络配置（含 WPA-PSK）
   └─ 或（RTL 设备）被动抓取 M7 后离线解密出 WPA-PSK
```

## 四、为什么一分钟内就能破解

传统在线 PIN 暴力需对 AP 逐次尝试约 11000 种 PIN，且易触发锁 PIN。
Pixie Dust 把最耗时的部分（找 PIN 对应的 E-S1/E-S2）变成 **本地离线枚举**，
因为 E-S1/E-S2 的可预测性使得 PIN 空间可被哈希快速校验，无需与 AP 交互。

## 五、防御

1. 仅使用 **WPA3**（WPA2/WPA3 混合模式也会触发该漏洞）。
2. 彻底 **关闭 WPS**。
3. 小米/Redmi 旧款固件默认开启且无法关闭 WPS → **更换设备**（AX3000 之后疑似已修复）。
