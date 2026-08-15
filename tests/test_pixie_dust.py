"""
单元测试：用公开的真实测试向量验证核心引擎。

测试向量来源：pixiewps 社区公开示例（octocathub / Kali 文档），
这是「E-S1 = E-S2 = 0」（RT 空 nonce）场景，已知正确输出：
  ES1 = ES2 = 00 * 16
  PSK1 = d4eb0c2a3815e1a03d70db7431eb53a3
  PSK2 = d3b7e623f31d220a23ea07bb7f76658b
  WPS pin = 04847533
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pixie_dust import (
    crack_first_half,
    crack_second_half,
    _crack,
    hmac_sha256,
    hex_to_bytes,
    pixie_attack,
)

AUTHKEY = (
    "7f:de:11:b9:69:1c:de:26:4a:21:a4:6f:eb:3d:b8:aa:"
    "aa:d7:30:09:09:32:b8:24:43:9b:e0:91:78:e7:6f:2c"
)
PKE = (
    "d4:38:91:0d:4e:6e:15:fe:70:f0:97:a8:70:2a:b8:94:"
    "f5:75:74:bf:64:19:9f:92:82:9b:e0:2c:c0:a3:75:48:"
    "08:8f:63:0a:82:37:0c:b7:95:42:cf:55:ca:a5:f0:f7:"
    "6c:b2:c7:5f:0e:23:18:44:f4:2d:00:f1:da:d4:94:23:"
    "56:c7:2c:b0:f6:87:c7:77:d0:cc:11:35:cf:b7:4f:bc:"
    "44:8d:ca:35:8a:78:3d:99:7f:2b:cf:44:21:d8:e2:0f:"
    "3c:7d:a4:72:c8:03:6f:77:2a:e9:fa:c1:e9:a8:2c:74:"
    "65:99:5a:e0:a5:26:d9:23:5e:4e:ec:5a:07:07:ab:80:"
    "db:3f:5f:18:7f:fa:fa:f1:57:74:b2:8d:a9:97:a6:c6:"
    "0a:a5:e0:ec:93:09:23:67:f6:3e:ec:1f:55:32:a4:5d:"
    "73:8f:ab:91:74:cf:1d:79:85:12:c1:81:f5:ea:a6:68:"
    "9d:8e:c7:c6:be:01:dc:d9:f8:68:80:11:55:d7:44:6a"
)
PKR = (
    "bc:ad:54:2f:88:44:7c:12:69:ef:34:31:4a:17:1c:92:"
    "b1:d7:06:4c:73:be:9f:d3:ed:87:63:74:10:46:0f:46:"
    "8c:36:b5:d4:a0:ba:af:85:9c:b2:30:42:d7:59:43:75:"
    "5a:d7:79:96:fb:ee:7b:66:db:b7:a8:f9:22:9c:a5:d3:"
    "b8:e7:c0:c4:5c:58:34:1f:56:a8:1a:41:a8:d2:e8:f6:"
    "3e:c9:3a:93:d9:9b:59:5c:a8:e0:78:84:6c:fc:05:e8:"
    "76:a3:e6:3b:33:94:4a:a9:ff:50:fb:60:fa:97:3b:6d:"
    "cc:04:f1:5e:36:24:a9:06:7a:f8:6b:00:e9:71:9d:89:"
    "be:9c:b2:9c:1f:ca:6d:d6:4d:ab:46:3d:b3:11:1f:8d:"
    "40:f7:c8:a4:39:48:c5:ca:1b:f6:30:95:7d:d9:68:41:"
    "ef:0a:37:b2:4a:37:e4:a4:b0:dd:7e:c1:af:3e:66:ea:"
    "bf:16:0a:7a:8a:05:00:01:a4:29:77:a9:d4:81:d4:0e"
)
E_HASH1 = "90:5f:f5:7d:93:e5:c4:3c:62:0d:26:65:dd:59:57:d5:ba:ba:f1:b7:30:91:72:7c:54:94:38:08:1e:13:35:38"
E_HASH2 = "b0:2b:07:50:28:e7:6e:5f:fa:27:1b:31:92:85:43:cb:c5:6a:ec:73:e2:27:c3:b9:80:ec:5b:ed:88:f0:1e:ec"

EXPECTED_PIN = "04847533"
EXPECTED_PSK1 = "d4eb0c2a3815e1a03d70db7431eb53a3"
EXPECTED_PSK2 = "d3b7e623f31d220a23ea07bb7f76658b"


def test_empty_psk():
    authkey = hex_to_bytes(AUTHKEY)
    empty_psk = hmac_sha256(authkey, b"")
    # empty psk 只校验长度与确定性（无公开向量值）
    assert len(empty_psk) == 32
    assert empty_psk == hmac_sha256(authkey, b"")


def test_crack_core():
    authkey = hex_to_bytes(AUTHKEY)
    pke = hex_to_bytes(PKE)
    pkr = hex_to_bytes(PKR)
    h1 = hex_to_bytes(E_HASH1)
    h2 = hex_to_bytes(E_HASH2)
    empty_psk = hmac_sha256(authkey, b"")
    es = bytes(16)

    st1, half1, psk1 = crack_first_half(authkey, empty_psk, es, pke, pkr, h1)
    assert st1 == 1, f"前半破解失败: {st1}"
    assert half1 == EXPECTED_PIN[:4], f"前半 PIN 错误: {half1}"
    assert psk1.hex() == EXPECTED_PSK1, f"PSK1 错误: {psk1.hex()}"

    st2, pin, psk2 = crack_second_half(authkey, empty_psk, es, pke, pkr, h2, half1)
    assert st2 == 1, "后半破解失败"
    assert pin == EXPECTED_PIN, f"完整 PIN 错误: {pin}"
    assert psk2.hex() == EXPECTED_PSK2, f"PSK2 错误: {psk2.hex()}"


def test_full_crack():
    authkey = hex_to_bytes(AUTHKEY)
    pke = hex_to_bytes(PKE)
    pkr = hex_to_bytes(PKR)
    h1 = hex_to_bytes(E_HASH1)
    h2 = hex_to_bytes(E_HASH2)
    empty_psk = hmac_sha256(authkey, b"")
    ok, pin, psk1, psk2 = _crack(authkey, empty_psk, bytes(16), bytes(16), pke, pkr, h1, h2)
    assert ok, "完整破解失败"
    assert pin == EXPECTED_PIN
    assert psk1.hex() == EXPECTED_PSK1
    assert psk2.hex() == EXPECTED_PSK2


def test_wps_pin_checksum():
    from core.pixie_dust import wps_pin_checksum, wps_pin_valid
    # 04847533 的校验位应为 3
    assert wps_pin_checksum(484753) == 3
    assert wps_pin_valid(4847533)
    assert not wps_pin_valid(4847530)


if __name__ == "__main__":
    test_empty_psk()
    test_crack_core()
    test_full_crack()
    test_wps_pin_checksum()
    print("所有核心单元测试通过 ✓")
    print(f"  PIN  : {EXPECTED_PIN}")
    print(f"  PSK1 : {EXPECTED_PSK1}")
    print(f"  PSK2 : {EXPECTED_PSK2}")
