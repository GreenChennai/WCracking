"""WCracking — WPS Pixie Dust 离线破解引擎（纯 Python 移植）。

本模块是 pixiewps (https://github.com/wiire-a/pixiewps, GPL-3.0) 的忠实 Python 移植，
仅依赖标准库 (hashlib / hmac / struct)。用于对**本人拥有或已获书面授权**的无线网络
进行安全审计。

原理解释（对应原 C 代码注释）：
  WPS 握手（M1-M7）中，Enrollee 会在 M1 发送 E-Nonce(N1)、PKe，
  M2 返回 PKr、R-Nonce，M3 发送 E-Hash1/E-Hash2（对 PIN 前后两半的 HMAC 校验值）。
  部分路由器（Ralink/Realtek/MediaTek/Broadcom 早期型号）用于生成秘密随机数
  E-S1/E-S2 的 PRNG 熵过低（甚至固定），因此可以离线枚举 PRNG 种子恢复 E-S1/E-S2，
  再用 E-Hash1/E-Hash2 校验暴力还原 8 位 WPS PIN（前半 10000 种、后半约 1000 种）。
"""

__version__ = "1.0.0"

from .pixie_dust import (
    pixie_attack,
    PixieResult,
    crack_first_half,
    crack_second_half,
    hex_to_bytes,
    MODE_NAME,
    RT,
    ECOS_SIMPLE,
    RTL819x,
    ECOS_SIMPLEST,
    ECOS_KNUTH,
)

__all__ = [
    "pixie_attack",
    "PixieResult",
    "crack_first_half",
    "crack_second_half",
    "hex_to_bytes",
    "MODE_NAME",
    "RT",
    "ECOS_SIMPLE",
    "RTL819x",
    "ECOS_SIMPLEST",
    "ECOS_KNUTH",
]
