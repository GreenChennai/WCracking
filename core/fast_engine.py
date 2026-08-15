"""Rust 加速引擎自动快速路径。

检测 `wcracking-engine`（Rust 版离线引擎）二进制，存在则通过 subprocess 调用并把输出
解析回 `PixieResult`，供 `pixie_dust.pixie_attack` 自动优先使用（GUI 也因此自动受益）。

查找顺序：
  1. PyInstaller 打包资源目录（sys._MEIPASS）
  2. 项目内 engine/target/release/
  3. 与可执行文件同目录（打包后）
  4. PATH
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

from .pixie_dust import PixieResult

ENGINE_NAMES = ("wcracking-engine", "wcracking-engine.exe")


def find_engine_binary():
    # 0. PyInstaller 打包资源目录
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        for name in ENGINE_NAMES:
            cand = os.path.join(meipass, name)
            if os.path.isfile(cand):
                return cand

    # 1. 项目内 engine/target/release/
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ENGINE_NAMES:
        cand = os.path.join(base, "engine", "target", "release", name)
        if os.path.isfile(cand):
            return cand

    # 2. 与可执行文件同目录（非 onefile 打包）
    exe_dir = os.path.dirname(sys.executable)
    for name in ENGINE_NAMES:
        cand = os.path.join(exe_dir, name)
        if os.path.isfile(cand):
            return cand

    # 3. PATH
    for name in ENGINE_NAMES:
        p = shutil.which(name)
        if p:
            return p
    return None


def has_fast_engine() -> bool:
    return find_engine_binary() is not None


def run_fast(
    pke, pkr, e_hash1, e_hash2, e_nonce,
    authkey=None, r_nonce=None, e_bssid=None, mode=None, force=False,
) -> PixieResult:
    """调用 Rust 引擎并解析输出。找不到二进制或调用失败时返回 None（回退 Python）。"""
    binary = find_engine_binary()
    if not binary:
        return None

    cmd = [binary, "--pke", pke, "--pkr", pkr,
           "--e-hash1", e_hash1, "--e-hash2", e_hash2, "--e-nonce", e_nonce]
    if authkey:
        cmd += ["--authkey", authkey]
    elif r_nonce and e_bssid:
        cmd += ["--r-nonce", r_nonce, "--e-bssid", e_bssid]
    else:
        return None  # 缺参数，交给 Python 引擎报错
    if mode:
        cmd += ["--mode", str(mode)]
    if force:
        cmd += ["--force"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return None

    out = proc.stdout or ""
    res = PixieResult()

    m_pin = re.search(r"\[\+\] WPS pin: (.+)", out)
    if not m_pin:
        res.found = False
        m_warn = re.search(r"\[-\] (.+)", out)
        if m_warn:
            res.warning = m_warn.group(1).strip()
        return res

    res.found = True
    res.pin = m_pin.group(1).strip()
    if res.pin == "<empty>":
        res.pin = ""

    m_mode = re.search(r"\[\?\] Mode:\s+(\d+)\s+\(([^)]+)\)", out)
    if m_mode:
        res.mode = int(m_mode.group(1))
        res.mode_name = m_mode.group(2)

    for key, attr in (("ES1", "es1"), ("ES2", "es2"), ("PSK1", "psk1"), ("PSK2", "psk2")):
        m = re.search(rf"\[\*\] {key}:\s+([0-9a-fA-F]+)", out)
        if m:
            setattr(res, attr, bytes.fromhex(m.group(1)))

    m_time = re.search(r"Time taken: ([\d.]+) s", out)
    if m_time:
        res.elapsed = float(m_time.group(1))
    res.notes.append("Rust 加速引擎")
    return res
