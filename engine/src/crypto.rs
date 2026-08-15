//! 加密原语（与 core/pixie_dust.py 逐行对应）。

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const WPS_PIN_LEN: usize = 8;
pub const WPS_PKEY_LEN: usize = 192;
pub const WPS_HASH_LEN: usize = 32;
pub const WPS_AUTHKEY_LEN: usize = 32;
pub const WPS_EMSK_LEN: usize = 32;
pub const WPS_KEYWRAPKEY_LEN: usize = 16;
pub const WPS_NONCE_LEN: usize = 16;
pub const WPS_SECRET_NONCE_LEN: usize = 16;
pub const WPS_PSK_LEN: usize = 16;
pub const WPS_BSSID_LEN: usize = 6;

pub const KDF_SALT: &[u8] = b"Wi-Fi Easy and Secure Key Derivation";

pub const DH_GROUP5_PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

pub const WPS_RTL_PKE_HEX: &str = "D0141B15656E96B85FCEAD2E8E76330D2B1AC1576BB026E7\
A328C0E1BAF8CF91664371174C08EE12EC92B0519C54879F\
21255BE5A8770E1FA1880470EF423C90E34D7847A6FCB492\
4563D1AF1DB0C481EAD9852C519BF1DD429C163951CF6918\
1B132AEA2A3684CAF35BC54ACA1B20C88BB3B7339FF7D56E\
09139D77F0AC58079097938251DBBE75E86715CC6B7C0CA9\
45FA8DD8D661BEB73B414032798DADEE32B5DD61BF105F18\
D89217760B75C5D966A5A490472CEBA9E3B4224F3D89FB2B";

/// 把 hex 串（可含 `:` `-` 空格）转字节。
pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    let mut hex = cleaned;
    if hex.len() % 2 != 0 {
        hex.insert(0, '0');
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// KDF：输出 AuthKey(32) || KeyWrapKey(16) || EMSK(32) = 96 字节。
pub fn kdf(kdk: &[u8]) -> Vec<u8> {
    let kdk_len = ((WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN) * 8) as u32;
    let mut out = Vec::with_capacity(96);
    for i in 1u32..4 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&i.to_be_bytes());
        buf.extend_from_slice(KDF_SALT);
        buf.extend_from_slice(&kdk_len.to_be_bytes());
        out.extend_from_slice(&hmac_sha256(kdk, &buf));
    }
    out
}

pub fn wps_pin_checksum(mut pin: u32) -> u32 {
    let mut acc = 0u32;
    while pin != 0 {
        acc += 3 * (pin % 10);
        pin /= 10;
        acc += pin % 10;
        pin /= 10;
    }
    (10 - acc % 10) % 10
}

pub fn wps_pin_valid(pin: u32) -> bool {
    wps_pin_checksum(pin / 10) == pin % 10
}

pub fn check_small_dh_keys(data: &[u8]) -> bool {
    let mut i = (WPS_PKEY_LEN - 2) as isize;
    loop {
        i -= 1;
        if i == 0 || data[i as usize] != 0 {
            break;
        }
    }
    i == 0 && data[WPS_PKEY_LEN - 1] == 0x02
}

/// DHKey = SHA-256(g^(AB) mod p)。small_dh_keys 时 = SHA-256(PKe)；RTL 时 = SHA-256(PKr^A mod p)。
pub fn compute_dhkey(pke: &[u8], pkr: &[u8], small_dh_keys: bool) -> Vec<u8> {
    if small_dh_keys {
        return sha256(pke);
    }
    let priv_key = BigUint::from_bytes_be(&vec![0x55u8; WPS_PKEY_LEN]);
    let prime = BigUint::from_str_radix(DH_GROUP5_PRIME_HEX, 16).unwrap();
    let pkr_int = BigUint::from_bytes_be(pkr);
    let dh = pkr_int.modpow(&priv_key, &prime);
    let mut dh_bytes = dh.to_bytes_be();
    while dh_bytes.len() < WPS_PKEY_LEN {
        dh_bytes.insert(0, 0);
    }
    sha256(&dh_bytes)
}
