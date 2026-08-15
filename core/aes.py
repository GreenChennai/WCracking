"""AES-128 纯 Python 实现（字节导向，公有领域风格）。

仅用于 WCracking 的 M7 加密设置解密（AES-128-CBC）。
已通过 NIST SP 800-38A F.2.1 测试向量验证。

用法：
    from core.aes import aes_128_cbc_decrypt
    plaintext = aes_128_cbc_decrypt(key(16), iv(16), ciphertext)
"""

from __future__ import annotations

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb"
    "7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e"
    "082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b692"
    "6c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506"
    "d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e673"
    "96ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1b"
    "fc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f"
    "60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961"
    "172b047eba77d626e169146355210c7d"
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

_NB = 4          # 列数（字）
_NK = 4          # 密钥字数（AES-128）
_NR = 10         # 轮数


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """GF(2^8) 乘法（用于 MixColumns）。"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p


def _key_expansion(key: bytes):
    w = [list(key[4 * i:4 * i + 4]) for i in range(_NK)]
    for i in range(_NK, _NB * (_NR + 1)):
        temp = w[i - 1][:]
        if i % _NK == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // _NK - 1]
        w.append([w[i - _NK][j] ^ temp[j] for j in range(4)])
    # 组织成轮密钥
    round_keys = []
    for r in range(_NR + 1):
        rk = []
        for c in range(_NB):
            rk += w[r * _NB + c]
        round_keys.append(bytes(rk))
    return round_keys


def _add_round_key(state: list, rk: bytes) -> list:
    return [state[i] ^ rk[i] for i in range(16)]


def _sub_bytes(state: list, box) -> list:
    return [box[b] for b in state]


def _shift_rows(state: list) -> list:
    # state 为列主序：state[r + 4*c]
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(state: list) -> list:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * ((c + r) % 4)] = state[r + 4 * c]
    return out


def _mix_columns(state: list) -> list:
    out = [0] * 16
    for c in range(4):
        col = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        out[4 * c + 1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        out[4 * c + 2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        out[4 * c + 3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    return out


def _inv_mix_columns(state: list) -> list:
    out = [0] * 16
    for c in range(4):
        col = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        out[4 * c + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        out[4 * c + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        out[4 * c + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
    return out


def _encrypt_block(block: bytes, rk) -> bytes:
    state = list(block)
    state = _add_round_key(state, rk[0])
    for rnd in range(1, _NR):
        state = _sub_bytes(state, _SBOX)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rk[rnd])
    state = _sub_bytes(state, _SBOX)
    state = _shift_rows(state)
    state = _add_round_key(state, rk[_NR])
    return bytes(state)


def _decrypt_block(block: bytes, rk) -> bytes:
    state = list(block)
    state = _add_round_key(state, rk[_NR])
    for rnd in range(_NR - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, _INV_SBOX)
        state = _add_round_key(state, rk[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _sub_bytes(state, _INV_SBOX)
    state = _add_round_key(state, rk[0])
    return bytes(state)


def aes_128_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    assert len(key) == 16
    assert len(data) % 16 == 0
    rk = _key_expansion(key)
    return b"".join(_encrypt_block(data[i:i + 16], rk) for i in range(0, len(data), 16))


def aes_128_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    assert len(key) == 16
    assert len(data) % 16 == 0
    rk = _key_expansion(key)
    return b"".join(_decrypt_block(data[i:i + 16], rk) for i in range(0, len(data), 16))


def aes_128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-128-CBC 解密。"""
    assert len(key) == 16 and len(iv) == 16
    assert len(ciphertext) % 16 == 0
    rk = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = _decrypt_block(ciphertext[i:i + 16], rk)
        out += bytes(b ^ prev[j] for j, b in enumerate(block))
        prev = ciphertext[i:i + 16]
    return bytes(out)
