"""WCracking — 桌面 GUI（PyQt6）。

离线 Pixie Dust 破解控制器：填入 WPS 握手数据 → 后台线程离线还原 PIN。

仅限对本人拥有或已获书面授权的网络进行安全审计。
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QTextEdit, QComboBox, QFormLayout, QVBoxLayout, QHBoxLayout,
    QGroupBox, QMessageBox, QInputDialog, QApplication as _QA,
)

from core.pixie_dust import pixie_attack, MODE_NAME, RT, ECOS_SIMPLE, RTL819x, ECOS_SIMPLEST, ECOS_KNUTH
from core.parser import parse_handshake

DISCLAIMER = (
    "⚠️ 本工具仅限对本人拥有或已获书面授权的网络进行安全审计。\n"
    "   未经授权破解他人 Wi-Fi 属违法行为，请自行承担法律责任。"
)


class CrackWorker(QThread):
    """后台执行离线破解，避免阻塞 UI。"""
    finished_ok = pyqtSignal(object)   # PixieResult
    failed = pyqtSignal(str)           # 错误信息

    def __init__(self, params, parent=None):
        super().__init__(parent)
        self.params = params

    def run(self):
        try:
            res = pixie_attack(**self.params)
            self.finished_ok.emit(res)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WCracking — WPS Pixie Dust 安全审计")
        self.resize(760, 720)
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # 免责声明
        warn = QLabel(DISCLAIMER)
        warn.setStyleSheet(
            "QLabel{background:#fff3cd;color:#7a5b00;border:1px solid #f0d18a;"
            "border-radius:6px;padding:8px;}"
        )
        warn.setWordWrap(True)
        root.addWidget(warn)

        # 输入组
        gb_input = QGroupBox("握手数据（由 reaver / OneShot 抓取）")
        form = QFormLayout(gb_input)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.ed_pke = self._make_hex_input()
        self.ed_pkr = self._make_hex_input()
        self.ed_hash1 = self._make_hex_input()
        self.ed_hash2 = self._make_hex_input()
        self.ed_authkey = self._make_hex_input()
        self.ed_nonce = self._make_hex_input()
        self.ed_rnonce = self._make_hex_input()
        self.ed_bssid = self._make_hex_input()

        form.addRow("PKe (192B)", self.ed_pke)
        form.addRow("PKr (192B)", self.ed_pkr)
        form.addRow("E-Hash1 (32B)", self.ed_hash1)
        form.addRow("E-Hash2 (32B)", self.ed_hash2)
        form.addRow("AuthKey (32B)", self.ed_authkey)
        form.addRow("E-Nonce (16B)", self.ed_nonce)
        form.addRow("R-Nonce (16B, 可选)", self.ed_rnonce)
        form.addRow("BSSID (6B, 可选)", self.ed_bssid)
        root.addWidget(gb_input)

        # 控制行
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("模式："))
        self.cb_mode = QComboBox()
        self.cb_mode.addItem("自动", None)
        for m in (RT, ECOS_SIMPLE, RTL819x, ECOS_SIMPLEST, ECOS_KNUTH):
            self.cb_mode.addItem(f"{m} - {MODE_NAME[m]}", m)
        self.cb_mode.setCurrentIndex(0)
        ctrl.addWidget(self.cb_mode)
        ctrl.addStretch(1)

        self.btn_crack = QPushButton("开始破解")
        self.btn_crack.clicked.connect(self._on_crack)
        ctrl.addWidget(self.btn_crack)

        self.btn_parse = QPushButton("粘贴 OneShot/reaver 输出自动填充")
        self.btn_parse.clicked.connect(self._on_parse)
        ctrl.addWidget(self.btn_parse)

        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._on_clear)
        ctrl.addWidget(self.btn_clear)
        root.addLayout(ctrl)

        # 输出
        gb_out = QGroupBox("结果")
        ov = QVBoxLayout(gb_out)
        self.out = QTextEdit()
        self.out.setReadOnly(True)
        self.out.setPlaceholderText("结果将显示在这里……")
        ov.addWidget(self.out)

        self.btn_copy = QPushButton("复制结果")
        self.btn_copy.clicked.connect(self._on_copy)
        ov.addWidget(self.btn_copy)
        root.addWidget(gb_out, 1)

    def _make_hex_input(self) -> QLineEdit:
        e = QLineEdit()
        e.setPlaceholderText("十六进制，可含 : 分隔")
        return e

    def _collect(self) -> dict:
        pke = self.ed_pke.text().strip()
        pkr = self.ed_pkr.text().strip()
        h1 = self.ed_hash1.text().strip()
        h2 = self.ed_hash2.text().strip()
        auth = self.ed_authkey.text().strip()
        nonce = self.ed_nonce.text().strip()
        rnonce = self.ed_rnonce.text().strip()
        bssid = self.ed_bssid.text().strip()

        if not all([pke, pkr, h1, h2, nonce]):
            raise ValueError("PKe / PKr / E-Hash1 / E-Hash2 / E-Nonce 为必填项。")
        if not auth and not (rnonce and bssid):
            raise ValueError("未填 AuthKey 时，必须同时填 R-Nonce 与 BSSID。")

        params = dict(
            pke=pke, pkr=pkr, e_hash1=h1, e_hash2=h2, e_nonce=nonce,
            mode=self.cb_mode.currentData(),
        )
        if auth:
            params["authkey"] = auth
        if rnonce:
            params["r_nonce"] = rnonce
        if bssid:
            params["e_bssid"] = bssid
        return params

    def _on_crack(self):
        try:
            params = self._collect()
        except ValueError as e:
            QMessageBox.warning(self, "输入有误", str(e))
            return

        self.btn_crack.setEnabled(False)
        self.out.append("[*] 开始离线破解……")
        self._worker = CrackWorker(params)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()

    def _on_done(self, res):
        self.btn_crack.setEnabled(True)
        lines = []
        if res.found:
            lines.append(f"[+] WPS PIN : {res.pin if res.pin else '<empty>'}")
            if res.mode_name:
                lines.append(f"[?] 模式    : {res.mode} ({res.mode_name})")
            if res.es1:
                lines.append(f"[*] ES1     : {res.es1.hex()}")
            if res.es2:
                lines.append(f"[*] ES2     : {res.es2.hex()}")
            if res.psk1:
                lines.append(f"[*] PSK1    : {res.psk1.hex()}")
            if res.psk2:
                lines.append(f"[*] PSK2    : {res.psk2.hex()}")
        else:
            lines.append("[-] 未找到 PIN（目标可能不易受此攻击，或需换更新握手数据 / --force）。")
            if res.warning:
                lines.append(f"[!] {res.warning}")
        lines.append(f"[*] 用时    : {res.elapsed:.2f} s")
        self.out.append("\n".join(lines))

    def _on_fail(self, msg):
        self.btn_crack.setEnabled(True)
        self.out.append(f"[x] 出错：{msg}")

    def _on_parse(self):
        """弹窗粘贴 OneShot -X / reaver 输出，自动提取并填充握手字段。"""
        text, ok = QInputDialog.getMultiLineText(
            self, "粘贴握手数据",
            "粘贴 OneShot（-X/--show-pixie-cmd）或 reaver 的输出，\n"
            "程序会自动提取 PKe/PKr/Hash/AuthKey/Nonce：", "")
        if not ok or not text.strip():
            return
        data = parse_handshake(text)
        if not data:
            QMessageBox.warning(self, "解析失败", "未能从文本中识别出任何握手字段。")
            return

        field_map = {
            "pke": self.ed_pke, "pkr": self.ed_pkr,
            "e_hash1": self.ed_hash1, "e_hash2": self.ed_hash2,
            "authkey": self.ed_authkey, "e_nonce": self.ed_nonce,
            "r_nonce": self.ed_rnonce, "e_bssid": self.ed_bssid,
        }
        filled = []
        for key, editor in field_map.items():
            if key in data:
                editor.setText(data[key])
                filled.append(key)
        self.out.append(f"[*] 已自动填充字段：{', '.join(filled)}")

    def _on_copy(self):
        text = self.out.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.out.append("[*] 结果已复制到剪贴板。")

    def _on_clear(self):
        for ed in (self.ed_pke, self.ed_pkr, self.ed_hash1, self.ed_hash2,
                   self.ed_authkey, self.ed_nonce, self.ed_rnonce, self.ed_bssid):
            ed.clear()
        self.out.clear()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("WCracking")
    try:
        win = MainWindow()
        win.show()
    except Exception as e:  # noqa: BLE001
        QMessageBox.critical(None, "启动失败", f"程序启动出错：\n{e}")
        return 1
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
