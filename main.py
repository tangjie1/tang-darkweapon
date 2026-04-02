"""
唐门-暗之器 - 网络安全工具集
主程序入口 v1.1
"""
import sys
import os
from pathlib import Path

# 添加 fofa-scan / nuclei-scan 到路径
sys.path.insert(0, str(Path(__file__).parent / "fofa-scan"))
sys.path.insert(0, str(Path(__file__).parent / "nuclei-scan"))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QTabWidget, QMenuBar, QMenu, QDialog, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QGroupBox, QFormLayout, QPlainTextEdit, QFileDialog,
    QTabBar
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon, QAction

from gui import FofaScanTab, HACKER_STYLESHEET
from nuclei_tab import NucleiTab
from config_manager import ConfigManager


# ──────────────────────────────────────────────────────────
#  Cookie 测试线程（不变）
# ──────────────────────────────────────────────────────────
class TestCookieThread(QThread):
    """测试 Cookie 线程"""
    result_signal = pyqtSignal(bool, str)

    def __init__(self, cookie: str, auth: str = ""):
        super().__init__()
        self.cookie = cookie
        self.auth = auth

    def run(self):
        try:
            import requests
            from lxml import etree
            import base64
            from urllib.parse import quote

            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Cookie": self.cookie
            }
            if self.auth:
                headers["Authorization"] = self.auth

            check_keyword = "thinkphp"
            search_bs64 = quote(
                str(base64.b64encode(check_keyword.encode()), encoding="utf-8")
            )
            response = requests.get(
                "https://fofa.info/result?qbase64=%s&page=1&page_size=10"
                % search_bs64,
                headers=headers,
                timeout=15,
            )
            tree = etree.HTML(response.text)
            urllist = tree.xpath('//span[@class="hsxa-host"]/a/@href')

            if len(urllist) == 0:
                self.result_signal.emit(
                    False, "Cookie 无效或已过期，请检查 Cookie 是否正确！"
                )
            else:
                self.result_signal.emit(
                    True,
                    "Cookie 有效！测试搜索返回 %d 条结果。" % len(urllist)
                )
        except requests.exceptions.Timeout:
            self.result_signal.emit(False, "请求超时，请检查网络连接。")
        except requests.exceptions.ConnectionError:
            self.result_signal.emit(False, "连接错误，无法访问 Fofa。")
        except Exception as e:
            self.result_signal.emit(False, "测试出错: %s" % str(e))


# ──────────────────────────────────────────────────────────
#  Cookie 设置对话框
# ──────────────────────────────────────────────────────────
class CookieDialog(QDialog):
    def __init__(self, config: ConfigManager, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("Cookie 设置")
        self.setMinimumWidth(550)
        self.setMinimumHeight(450)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        help_text = (
            "【如何获取 Fofa Cookie】\n"
            "1. 使用浏览器登录 Fofa (fofa.info)\n"
            "2. 按 F12 打开开发者工具 → Network/网络\n"
            "3. 刷新页面，点击任意请求\n"
            "4. 在 Headers 中复制 Cookie 和 Authorization（如有）"
        )
        help_label = QLabel(help_text)
        help_label.setStyleSheet("color: #00aa33; font-size: 11px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)

        auth_group = QGroupBox("【 认证信息 】")
        auth_layout = QFormLayout(auth_group)

        self.cookie_input = QPlainTextEdit()
        self.cookie_input.setPlaceholderText("粘贴 Fofa Cookie 到这里...")
        self.cookie_input.setMaximumBlockCount(1)
        self.cookie_input.setMaximumHeight(60)
        cookie_value = self.config.get_cookie()
        if cookie_value:
            self.cookie_input.setPlainText(cookie_value.strip())
        auth_layout.addRow("Cookie:", self.cookie_input)

        self.auth_input = QLineEdit()
        self.auth_input.setPlaceholderText("Authorization (可选，某些账号需要)")
        self.auth_input.setText(self.config.get("fofa_authorization", ""))
        auth_layout.addRow("Authorization:", self.auth_input)

        layout.addWidget(auth_group)

        test_layout = QHBoxLayout()
        self.test_btn = QPushButton("🔍 测试 Cookie 有效性")
        self.test_btn.clicked.connect(self.test_cookie)
        test_layout.addWidget(self.test_btn)
        test_layout.addStretch()
        layout.addLayout(test_layout)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        self.save_btn = QPushButton("💾 保存")
        self.save_btn.clicked.connect(self.save_cookie)
        button_layout.addWidget(self.save_btn)
        layout.addLayout(button_layout)

        self.setStyleSheet(HACKER_STYLESHEET)

    def test_cookie(self):
        cookie = " ".join(self.cookie_input.toPlainText().strip().split())
        auth = self.auth_input.text().strip()
        if not cookie:
            QMessageBox.warning(self, "警告", "请先输入 Cookie")
            return
        self.test_btn.setEnabled(False)
        self.test_btn.setText("测试中...")
        self.test_thread = TestCookieThread(cookie, auth)
        self.test_thread.result_signal.connect(self._on_test_result)
        self.test_thread.start()

    def _on_test_result(self, valid: bool, msg: str):
        self.test_btn.setEnabled(True)
        self.test_btn.setText("🔍 测试 Cookie 有效性")
        if valid:
            QMessageBox.information(self, "测试成功", msg)
        else:
            QMessageBox.critical(self, "测试失败", msg)

    def save_cookie(self):
        cookie = " ".join(self.cookie_input.toPlainText().strip().split())
        auth = self.auth_input.text().strip()
        if not cookie:
            QMessageBox.warning(self, "警告", "Cookie 不能为空")
            return
        self.config.set_cookie(cookie)
        self.config.set("fofa_authorization", auth)
        self.config.save()
        QMessageBox.information(self, "成功", "配置已保存")
        self.accept()


# ──────────────────────────────────────────────────────────
#  Nuclei 全局设置对话框
# ──────────────────────────────────────────────────────────
class NucleiSettingsDialog(QDialog):
    """在主菜单「设置」里管理 nuclei 全局路径配置"""

    def __init__(self, config: ConfigManager, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("Nuclei 全局配置")
        self.setMinimumWidth(600)
        self.setStyleSheet(HACKER_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        help_lbl = QLabel(
            "【 Nuclei 全局配置 】\n"
            "此处配置的路径将被 Nuclei 扫描模块直接使用，\n"
            "无需在每次打开时重复设置。"
        )
        help_lbl.setStyleSheet("color:#00aa33;font-size:11px;")
        layout.addWidget(help_lbl)

        group = QGroupBox("【 路径配置 】")
        grid = QVBoxLayout(group)

        exe_row = QHBoxLayout()
        exe_lbl = QLabel("Nuclei EXE:")
        exe_lbl.setFixedWidth(110)
        self.exe_edit = QLineEdit(config.get("nuclei_exe", ""))
        self.exe_edit.setPlaceholderText("nuclei.exe 完整路径")
        exe_row.addWidget(exe_lbl)
        exe_row.addWidget(self.exe_edit)
        browse_exe = QPushButton("📂")
        browse_exe.setFixedWidth(36)
        browse_exe.clicked.connect(self._browse_exe)
        exe_row.addWidget(browse_exe)
        grid.addLayout(exe_row)

        tmpl_row = QHBoxLayout()
        tmpl_lbl = QLabel("模板目录:")
        tmpl_lbl.setFixedWidth(110)
        self.tmpl_edit = QLineEdit(config.get("nuclei_template_dir", ""))
        self.tmpl_edit.setPlaceholderText("nuclei-templates/ 目录路径")
        tmpl_row.addWidget(tmpl_lbl)
        tmpl_row.addWidget(self.tmpl_edit)
        browse_tmpl = QPushButton("📂")
        browse_tmpl.setFixedWidth(36)
        browse_tmpl.clicked.connect(self._browse_tmpl)
        tmpl_row.addWidget(browse_tmpl)
        grid.addLayout(tmpl_row)

        out_row = QHBoxLayout()
        out_lbl = QLabel("结果输出目录:")
        out_lbl.setFixedWidth(110)
        self.out_edit = QLineEdit(config.get("nuclei_output_dir", "output"))
        out_row.addWidget(out_lbl)
        out_row.addWidget(self.out_edit)
        browse_out = QPushButton("📂")
        browse_out.setFixedWidth(36)
        browse_out.clicked.connect(self._browse_out)
        out_row.addWidget(browse_out)
        grid.addLayout(out_row)

        layout.addWidget(group)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        save_btn = QPushButton("💾 保存")
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)
        layout.addLayout(btn_row)

    def _browse_exe(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "选择 nuclei 可执行文件", "",
            "可执行文件 (*.exe);;所有文件 (*)"
        )
        if p:
            self.exe_edit.setText(p)

    def _browse_tmpl(self):
        p = QFileDialog.getExistingDirectory(self, "选择 nuclei-templates 目录")
        if p:
            self.tmpl_edit.setText(p)

    def _browse_out(self):
        p = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if p:
            self.out_edit.setText(p)

    def _save(self):
        self.config.set("nuclei_exe", self.exe_edit.text().strip())
        self.config.set("nuclei_template_dir", self.tmpl_edit.text().strip())
        self.config.set("nuclei_output_dir", self.out_edit.text().strip())
        self.config.save()
        QMessageBox.information(self, "成功", "Nuclei 配置已保存")
        self.accept()


# ──────────────────────────────────────────────────────────
#  主窗口
# ──────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("唐门-暗之器  v1.1")
        self.setMinimumSize(1280, 860)

        self.config = ConfigManager("config")

        self.create_menu()
        self.create_main_ui()
        self.apply_hacker_theme()

    def create_menu(self):
        menubar = self.menuBar()

        tools_menu = menubar.addMenu("工具(T)")

        cookie_action = QAction("Fofa Cookie 设置", self)
        cookie_action.setShortcut("Ctrl+Shift+C")
        cookie_action.triggered.connect(self.show_cookie_dialog)
        tools_menu.addAction(cookie_action)

        nuclei_cfg_action = QAction("Nuclei 全局配置", self)
        nuclei_cfg_action.setShortcut("Ctrl+Shift+N")
        nuclei_cfg_action.triggered.connect(self.show_nuclei_settings)
        tools_menu.addAction(nuclei_cfg_action)

        tools_menu.addSeparator()

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        tools_menu.addAction(exit_action)

        help_menu = menubar.addMenu("帮助(H)")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_main_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(10, 10, 10, 10)

        self.tab_widget = QTabWidget()

        self.fofa_tab = FofaScanTab(self.config)
        self.tab_widget.addTab(self.fofa_tab, "🔍 Fofa 扫描")

        self.nuclei_tab = NucleiTab(self.config)
        self.nuclei_tab.request_switch_tab.connect(
            lambda: self.tab_widget.setCurrentIndex(1)
        )
        self.tab_widget.addTab(self.nuclei_tab, "⚡ Nuclei 扫描")

        self.fofa_tab.send_to_nuclei.connect(self._receive_fofa_targets)

        layout.addWidget(self.tab_widget)

        self.statusBar().showMessage("唐门-暗之器 v1.1 就绪")
        self.statusBar().setStyleSheet("color: #00ff41;")

    def _receive_fofa_targets(self, targets: list):
        self.nuclei_tab.add_targets(targets)
        self.tab_widget.setCurrentIndex(1)

    def apply_hacker_theme(self):
        self.setStyleSheet(HACKER_STYLESHEET)
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)

        self.menuBar().setStyleSheet("""
            QMenuBar {
                background-color: #0a0a0a;
                color: #00ff41;
                border-bottom: 1px solid #00ff41;
            }
            QMenuBar::item {
                background-color: transparent;
                color: #00ff41;
                padding: 5px 15px;
            }
            QMenuBar::item:selected {
                background-color: #00ff41;
                color: #0a0a0a;
            }
            QMenu {
                background-color: #0a0a0a;
                color: #00ff41;
                border: 1px solid #00ff41;
            }
            QMenu::item { padding: 5px 25px; }
            QMenu::item:selected {
                background-color: #00ff41;
                color: #0a0a0a;
            }
            QMenu::separator {
                height: 1px;
                background-color: #003300;
                margin: 5px 10px;
            }
            QTabWidget::pane {
                border: 1px solid #00ff41;
            }
            QTabBar::tab {
                background: #1a1a1a;
                color: #00ff41;
                border: 1px solid #003300;
                padding: 8px 20px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #0f2a0f;
                border-bottom: 2px solid #00ff41;
                color: #00ffff;
            }
            QTabBar::tab:hover {
                background: #1a3a1a;
            }
        """)

    def show_cookie_dialog(self):
        CookieDialog(self.config, self).exec()

    def show_nuclei_settings(self):
        dlg = NucleiSettingsDialog(self.config, self)
        if dlg.exec():
            self.nuclei_tab._load_config()

    def show_about(self):
        QMessageBox.about(
            self, "关于",
            "<h2 style='color:#00ff41;'>唐门-暗之器</h2>"
            "<p style='color:#cccccc;'>网络安全工具集</p>"
            "<p style='color:#888888;'>版本: 1.1.0</p>"
            "<br>"
            "<p style='color:#00aa33;'>⚠️ 本工具仅供安全研究和授权测试使用</p>"
            "<p style='color:#00aa33;'>⚠️ 请遵守相关法律法规</p>"
        )


def main():
    Path("config").mkdir(exist_ok=True)
    Path("output").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)

    app = QApplication(sys.argv)

    font = QFont("Consolas", 10)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
