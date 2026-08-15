"""OneShot / reaver 输出解析器 —— 从抓包工具的 verbose 输出中提取握手字段。

支持两种输入格式：
  1. pixiewps 命令行（OneShot -X / --show-pixie-cmd 打印）：
     pixiewps --pke <hex> --pkr <hex> --e-hash1 <hex> --e-hash2 <hex> --authkey <hex> --e-nonce <hex>
  2. reaver / OneShot 的 key: value 输出：
     [+] PKE: <hex>
     [+] PKR: <hex>
     [+] E-Hash1: <hex>
     ...

返回 dict，键：pke / pkr / e_hash1 / e_hash2 / authkey / e_nonce / r_nonce / e_bssid。
"""

from __future__ import annotations

import re

_HEX_TOKEN = r"[0-9a-fA-F][0-9a-fA-F:]*"


def _clean_hex(s: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", s)


# (canonical_key, pixiewps 长选项, key: value 匹配模式)
_FIELDS = [
    ("pke", "--pke", [r"pke", r"enrollee public key"]),
    ("pkr", "--pkr", [r"pkr", r"registrar public key"]),
    ("e_hash1", "--e-hash1", [r"e[-_ ]hash1", r"enrollee hash 1"]),
    ("e_hash2", "--e-hash2", [r"e[-_ ]hash2", r"enrollee hash 2"]),
    ("authkey", "--authkey", [r"authkey", r"auth key", r"authentication session key"]),
    ("e_nonce", "--e-nonce", [r"e[-_ ]nonce", r"enrollee nonce"]),
    ("r_nonce", "--r-nonce", [r"r[-_ ]nonce", r"registrar nonce"]),
    ("e_bssid", "--e-bssid", [r"e[-_ ]bssid"]),
]


def parse_handshake(text: str) -> dict:
    """从文本中提取握手字段，返回 dict（缺失字段不出现）。"""
    result: dict = {}
    for key, long_opt, patterns in _FIELDS:
        val = None
        # 1) pixiewps 命令行：--long-opt <hex>
        m = re.search(re.escape(long_opt) + r"\s+(" + _HEX_TOKEN + r")", text, re.IGNORECASE)
        if m:
            val = m.group(1)
        else:
            # 2) key: value 行
            for pat in patterns:
                m = re.search(pat + r"\s*[:=]\s*(" + _HEX_TOKEN + r")", text, re.IGNORECASE)
                if m:
                    val = m.group(1)
                    break
        if val:
            result[key] = _clean_hex(val)
    return result
