//! 各 PRNG 实现（与 core/pixie_dust.py 逐行对应，所有 32 位算术显式回绕）。

pub const GLIBC_SEED_TBL: [u32; 34] = [
    0x0128E83B, 0x00DAFA31, 0x009F4828, 0x00F66443, 0x00BEE24D, 0x00817005, 0x00CB918F,
    0x00A64845, 0x0069C3CF, 0x00A76DBD, 0x0090A848, 0x0057025F, 0x0089126C, 0x007D9A8F,
    0x0048252A, 0x006FB2D4, 0x006CCC15, 0x003C5744, 0x005A998F, 0x005DF917, 0x0032ED77,
    0x00492688, 0x0050E901, 0x002B5F57, 0x003ACD0B, 0x00456B7A, 0x0025413D, 0x002F11F4,
    0x003B564D, 0x00203F14, 0x002589FC, 0x003283F8, 0x001C17E4, 0x001DD823,
];

/// eCos 最简 LCG。返回 (新种子, 输出)。
pub fn ecos_rand_simplest(seed: u32) -> (u32, u32) {
    let s = seed.wrapping_mul(1103515245).wrapping_add(12345);
    (s, s)
}

/// eCos 简单 LCG。返回 (新种子, 输出)。
pub fn ecos_rand_simple(seed: u32) -> (u32, u32) {
    let mut s = seed;
    s = s.wrapping_mul(1103515245).wrapping_add(12345);
    let mut uret = s & 0xFFE0_0000;
    s = s.wrapping_mul(1103515245).wrapping_add(12345);
    uret = uret.wrapping_add((s & 0xFFFC_0000) >> 11);
    s = s.wrapping_mul(1103515245).wrapping_add(12345);
    uret = uret.wrapping_add((s & 0xFE00_0000) >> 25);
    (s, uret)
}

/// eCos Knuth（Park-Miller）。返回 (新种子, 输出)。
pub fn ecos_rand_knuth(seed: u32) -> (u32, u32) {
    let res = 48271i64 * (seed as i64 % 44488) - 3399i64 * (seed as i64 / 44488);
    let res = if res < 0 { res + 2147483647 } else { res };
    (res as u32, res as u32)
}

/// Ralink LFSR 向前生成一字节。返回 (新状态, 字节)。
pub fn ralink_randbyte(mut sreg: u32) -> (u32, u8) {
    let mut r = 0u8;
    for _ in 0..8 {
        let result;
        if sreg & 0x0000_0001 != 0 {
            sreg = ((sreg ^ 0x8000_0057) >> 1) | 0x8000_0000;
            result = 1;
        } else {
            sreg >>= 1;
            result = 0;
        }
        r = (r << 1) | result;
    }
    (sreg, r)
}

/// 从字节反推 LFSR 状态。
pub fn ralink_randstate_restore(mut sreg: u32, mut r: u8) -> u32 {
    for _ in 0..8 {
        let result = r & 1;
        r >>= 1;
        if result != 0 {
            sreg = ((sreg << 1) ^ 0x8000_0057) | 0x0000_0001;
        } else {
            sreg <<= 1;
        }
    }
    sreg
}

/// Ralink LFSR 向后生成一字节。返回 (新状态, 字节)。
pub fn ralink_randbyte_backwards(mut sreg: u32) -> (u32, u8) {
    let mut r = 0u8;
    for i in 0..8 {
        let result;
        if sreg & 0x8000_0000 != 0 {
            sreg = ((sreg << 1) ^ 0x8000_0057) | 0x0000_0001;
            result = 1;
        } else {
            sreg <<= 1;
            result = 0;
        }
        r |= result << i;
    }
    (sreg, r)
}

/// glibc random 快路径：由种子生成 nonce 的 4 个 32 位字。
pub fn glibc_fast_nonce(mut seed: u32) -> [u32; 4] {
    let mut word0 = 0u32;
    let mut word1 = 0u32;
    let mut word2 = 0u32;
    let mut word3 = 0u32;
    for j in 0..31 {
        word0 = word0.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j + 3]));
        word1 = word1.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j + 2]));
        word2 = word2.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j + 1]));
        word3 = word3.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j]));
        seed = ((16807u64 * seed as u64) % 0x7FFF_FFFF) as u32;
    }
    [word0 >> 1, word1 >> 1, word2 >> 1, word3 >> 1]
}

/// glibc random 快路径：由种子生成首个 32 位字。
pub fn glibc_fast_seed(mut seed: u32) -> u32 {
    let mut word0 = 0u32;
    for j in 3..33 {
        word0 = word0.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j]));
        seed = ((16807u64 * seed as u64) % 0x7FFF_FFFF) as u32;
    }
    word0 = word0.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[33]));
    word0 >> 1
}

/// Realtek 由种子生成 16 字节 nonce/ES（单次 digit-sum）。
pub fn rtl_nonce_fill(mut seed: u32) -> [u8; 16] {
    let mut word0 = 0u32;
    let mut word1 = 0u32;
    let mut word2 = 0u32;
    let mut word3 = 0u32;
    for j in 0..31 {
        word0 = word0.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j + 3]));
        word1 = word1.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j + 2]));
        word2 = word2.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j + 1]));
        word3 = word3.wrapping_add(seed.wrapping_mul(GLIBC_SEED_TBL[j]));
        let p = 16807u64 * seed as u64;
        seed = ((p >> 31) + (p & 0x7FFF_FFFF)) as u32;
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(word0 >> 1).to_be_bytes());
    out[4..8].copy_from_slice(&(word1 >> 1).to_be_bytes());
    out[8..12].copy_from_slice(&(word2 >> 1).to_be_bytes());
    out[12..16].copy_from_slice(&(word3 >> 1).to_be_bytes());
    out
}
