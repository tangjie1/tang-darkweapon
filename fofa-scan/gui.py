"""
Fofa 扫描 GUI 界面
黑客风格主题 - 黑底绿字
"""
import sys
import os
import warnings
from pathlib import Path
from datetime import datetime
from typing import Optional

# 屏蔽 HTTPS 自签名证书探测时的 InsecureRequestWarning
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSpinBox, QTableWidget, QTableWidgetItem,
    QProgressBar, QPlainTextEdit, QFileDialog, QMessageBox,
    QGroupBox, QGridLayout, QHeaderView, QComboBox,
    QDialog, QDialogButtonBox, QDoubleSpinBox, QSizePolicy,
    QTextEdit as _QTextEdit, QMenu, QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon

from spider import FofaSpider, save_results_to_file
from config_manager import ConfigManager


# ============ 黑客风格样式 ============
HACKER_STYLESHEET = """
QWidget {
    background-color: #0a0a0a;
    color: #00ff41;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
}

QMainWindow {
    background-color: #0a0a0a;
}

QGroupBox {
    border: 2px solid #00ff41;
    border-radius: 5px;
    margin-top: 10px;
    padding-top: 10px;
    font-weight: bold;
    color: #00ff41;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #00ff41;
}

QLineEdit {
    background-color: #1a1a1a;
    border: 1px solid #00ff41;
    border-radius: 3px;
    padding: 5px;
    color: #00ff41;
    selection-background-color: #00ff41;
    selection-color: #0a0a0a;
}

QLineEdit:focus {
    border: 2px solid #00ff41;
    background-color: #0f1f0f;
}

QSpinBox {
    background-color: #1a1a1a;
    border: 1px solid #00ff41;
    border-radius: 3px;
    padding: 5px;
    color: #00ff41;
}

QComboBox {
    background-color: #1a1a1a;
    border: 1px solid #00ff41;
    border-radius: 3px;
    padding: 5px;
    color: #00ff41;
}

QComboBox::drop-down {
    border: none;
}

QComboBox QAbstractItemView {
    background-color: #1a1a1a;
    color: #00ff41;
    selection-background-color: #00ff41;
    selection-color: #0a0a0a;
}

QPushButton {
    background-color: #1a1a1a;
    border: 2px solid #00ff41;
    border-radius: 5px;
    padding: 8px 20px;
    color: #00ff41;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #00ff41;
    color: #0a0a0a;
}

QPushButton:pressed {
    background-color: #00cc33;
}

QPushButton:disabled {
    border-color: #333333;
    color: #333333;
    background-color: #1a1a1a;
}

QTableWidget {
    background-color: #0f0f0f;
    border: 1px solid #00ff41;
    gridline-color: #003300;
    color: #00ff41;
}

QTableWidget::item {
    padding: 5px;
    border-bottom: 1px solid #003300;
}

QTableWidget::item:selected {
    background-color: #00ff41;
    color: #0a0a0a;
}

QHeaderView::section {
    background-color: #1a1a1a;
    color: #00ff41;
    padding: 8px;
    border: 1px solid #00ff41;
    font-weight: bold;
}

QProgressBar {
    border: 1px solid #00ff41;
    border-radius: 3px;
    text-align: center;
    color: #00ff41;
    background-color: #1a1a1a;
}

QProgressBar::chunk {
    background-color: #00ff41;
}

QTextEdit {
    background-color: #0f0f0f;
    border: 1px solid #00ff41;
    border-radius: 3px;
    padding: 5px;
    color: #00ff41;
    font-family: "Consolas", "Courier New", monospace;
}

QScrollBar:vertical {
    background-color: #1a1a1a;
    width: 12px;
    border: 1px solid #00ff41;
}

QScrollBar::handle:vertical {
    background-color: #00ff41;
    min-height: 20px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background-color: #1a1a1a;
}

QLabel {
    color: #00ff41;
}

QMessageBox {
    background-color: #0a0a0a;
}

QMessageBox QLabel {
    color: #00ff41;
}

QMessageBox QPushButton {
    min-width: 80px;
}
"""


class GetPagesThread(QThread):
    """获取总页数线程"""
    result_signal = pyqtSignal(bool, int, str)  # 是否成功, 总页数, 消息
    
    def __init__(self, cookie: str, keyword: str, auth: str = ""):
        super().__init__()
        self.cookie = cookie
        self.keyword = keyword
        self.auth = auth
        
    def run(self):
        """获取总页数 (适配 2026 年新版 FOFA)"""
        try:
            import requests
            from lxml import etree
            import base64
            from urllib.parse import quote
            import re
            
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Cookie": self.cookie
            }
            
            if self.auth:
                headers["Authorization"] = self.auth
                
            # 编码关键词
            search_bs64 = quote(str(base64.b64encode(self.keyword.encode()), encoding='utf-8'))
            
            # 请求第一页获取总页数
            response = requests.get(
                "https://fofa.info/result?qbase64=%s&page=1" % search_bs64,
                headers=headers,
                timeout=15
            )
            
            tree = etree.HTML(response.text)
            total_pages = 0
            total_count = 0
            
            try:
                # ===== 方法1: 从 el-pagination__total is-first 获取总条数 =====
                total_texts = tree.xpath(
                    '//span[contains(@class,"el-pagination__total")]/text()'
                )
                for text in total_texts:
                    m = re.search(r'共\s*(\d+)\s*条', text)
                    if m:
                        total_count = int(m.group(1))
                        total_pages = (total_count + 9) // 10
                        break
                
                # ===== 方法2: 从 el-pager 页码列表取最大页码 =====
                if total_pages == 0:
                    page_nums = tree.xpath(
                        '//ul[contains(@class,"el-pager")]/li/text()'
                    )
                    nums = []
                    for p in page_nums:
                        try:
                            nums.append(int(p.strip()))
                        except ValueError:
                            pass
                    if nums:
                        total_pages = max(nums)
                        
                # ===== 方法3: 正则从 HTML 文本直接提取 =====
                if total_pages == 0:
                    matches = re.findall(r'共\s*(\d+)\s*条', response.text)
                    if matches:
                        total_count = int(matches[0])
                        total_pages = (total_count + 9) // 10
                        
            except Exception as e:
                print("解析页数出错: %s" % e)
                total_pages = 0
            
            if total_pages > 0:
                msg = "共 %d 条结果，共 %d 页" % (total_count, total_pages) if total_count else "共 %d 页" % total_pages
                self.result_signal.emit(True, total_pages, msg)
            else:
                hosts = tree.xpath('//span[@class="hsxa-host"]/a[1]/@href')
                if len(hosts) == 0:
                    self.result_signal.emit(False, 0, "无法获取数据，请检查 Cookie 是否有效或搜索结果为空")
                else:
                    self.result_signal.emit(False, 0, "无法获取总页数（已找到结果，但页数解析失败）")
                
        except Exception as e:
            self.result_signal.emit(False, 0, str(e))


class SpiderThread(QThread):
    """爬虫工作线程"""
    progress_signal = pyqtSignal(int, int, str)  # 当前页, 总页数, 状态
    result_signal = pyqtSignal(list)  # 结果列表
    finished_signal = pyqtSignal(bool, str)  # 是否成功, 消息
    
    def __init__(self, spider: FofaSpider, keyword: str, start_page: int, end_page: int):
        super().__init__()
        self.spider = spider
        self.keyword = keyword
        self.start_page = start_page
        self.end_page = end_page
        self._is_running = True
        
    def run(self):
        try:
            results = self.spider.search(
                keyword=self.keyword,
                start_page=self.start_page,
                end_page=self.end_page,
                progress_callback=self._on_progress,
                result_callback=self._on_result
            )
            self.finished_signal.emit(True, f"爬取完成，共获取 {len(results)} 条结果")
        except Exception as e:
            self.finished_signal.emit(False, f"爬取失败: {str(e)}")
            
    def _on_progress(self, current: int, total: int, message: str):
        self.progress_signal.emit(current, total, message)
        
    def _on_result(self, results: list):
        self.result_signal.emit(results)
        
    def stop(self):
        self.spider.stop()
        
    def pause(self):
        self.spider.pause()
        
    def resume(self):
        self.spider.resume()


class ProbeThread(QThread):
    """Host 存活探测线程（手动触发）"""
    probe_result_signal = pyqtSignal(int, str, str)
    probe_finished_signal = pyqtSignal(int, int)

    def __init__(self, hosts: list, timeout: float = 5.0):
        super().__init__()
        self.hosts = hosts
        self.timeout = timeout
        self._stop_flag = False

    def run(self):
        import requests as _req
        alive = 0
        for row, url in self.hosts:
            if self._stop_flag:
                break
            try:
                resp = _req.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"
                        )
                    }
                )
                code = resp.status_code
                if code < 400:
                    status = "✅ %d" % code
                    color = "#00ff41"
                    alive += 1
                else:
                    status = "⚠ %d" % code
                    color = "#ffaa00"
            except _req.exceptions.SSLError:
                status = "⚠ SSL错误"
                color = "#ffaa00"
                alive += 1
            except _req.exceptions.ConnectionError:
                status = "❌ 无法连接"
                color = "#ff0041"
            except _req.exceptions.Timeout:
                status = "⏱ 超时"
                color = "#ff4400"
            except Exception as e:
                status = "❌ %s" % str(e)[:20]
                color = "#ff0041"
            self.probe_result_signal.emit(row, status, color)
        self.probe_finished_signal.emit(alive, len(self.hosts))

    def stop(self):
        self._stop_flag = True


class ResultDetailDialog(QDialog):
    """双击行时弹出的完整详情对话框"""

    def __init__(self, row_data: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("资产详情")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        self.setStyleSheet(HACKER_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title_lbl = QLabel("[ 资产详情 ]")
        title_lbl.setStyleSheet(
            "color: #00ffff; font-size: 14px; font-weight: bold;"
        )
        layout.addWidget(title_lbl)

        fields = [
            ("Host",   row_data.get("host",     "")),
            ("IP",     row_data.get("ip",        "")),
            ("Port",   row_data.get("port",      "")),
            ("协议",   row_data.get("protocol",  "")),
            ("标题",   row_data.get("title",     "")),
            ("状态",   row_data.get("status",    "未探测")),
        ]

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        for r, (key, val) in enumerate(fields):
            key_lbl = QLabel("%s:" % key)
            key_lbl.setStyleSheet("color: #00aa33; font-weight: bold;")
            key_lbl.setFixedWidth(60)
            val_edit = _QTextEdit()
            val_edit.setReadOnly(True)
            val_edit.setPlainText(val)
            val_edit.setStyleSheet(
                "background:#0f0f0f; border:1px solid #003300; "
                "color:#00ff41; font-family:Consolas,monospace;"
            )
            line_h = val_edit.fontMetrics().lineSpacing()
            lines = max(1, len(val) // 60 + 1)
            val_edit.setFixedHeight(min(lines * line_h + 18, 120))
            grid.addWidget(key_lbl, r, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(val_edit, r, 1)

        layout.addLayout(grid)

        hint = QLabel(
            "提示：可直接复制上方文本框内容"
        )
        hint.setStyleSheet("color: #005500; font-size: 11px;")
        layout.addWidget(hint)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        btn_box.setStyleSheet(
            "QDialogButtonBox QPushButton {padding: 6px 24px;}"
        )
        layout.addWidget(btn_box)


class FofaScanTab(QWidget):
    """Fofa 扫描标签页"""

    send_to_nuclei = pyqtSignal(list)
    
    def __init__(self, config: ConfigManager, parent=None):
        super().__init__(parent)
        self.config = config
        self.spider: Optional[FofaSpider] = None
        self.spider_thread: Optional[SpiderThread] = None
        self.probe_thread: Optional[ProbeThread] = None
        self.all_results = []
        self.init_ui()
        self.apply_hacker_theme()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # ===== 搜索配置区域 =====
        search_group = QGroupBox("【 搜索配置 】")
        search_layout = QGridLayout()
        
        # 关键词
        search_layout.addWidget(QLabel("搜索关键词:"), 0, 0)
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("输入 Fofa 搜索语法，如: app=\"Apache-Shiro\"")
        search_layout.addWidget(self.keyword_input, 0, 1, 1, 5)
        
        # 页码范围
        search_layout.addWidget(QLabel("起始页:"), 1, 0)
        self.start_page = QSpinBox()
        self.start_page.setRange(1, 9999)
        self.start_page.setValue(1)
        search_layout.addWidget(self.start_page, 1, 1)
        
        search_layout.addWidget(QLabel("结束页:"), 1, 2)
        self.end_page = QSpinBox()
        self.end_page.setRange(1, 9999)
        self.end_page.setValue(5)
        search_layout.addWidget(self.end_page, 1, 3)
        
        self.get_pages_btn = QPushButton("🔍 获取页数")
        self.get_pages_btn.clicked.connect(self.get_total_pages)
        search_layout.addWidget(self.get_pages_btn, 1, 4)
        
        search_layout.addWidget(QLabel("总页数:"), 1, 5)
        self.total_pages_label = QLabel("-")
        self.total_pages_label.setStyleSheet("color: #00ff41; font-weight: bold;")
        search_layout.addWidget(self.total_pages_label, 1, 6)

        # ── 爬取间隔时间 ──
        search_layout.addWidget(QLabel("间隔(秒):"), 2, 0)
        delay_layout = QHBoxLayout()
        self.delay_min = QDoubleSpinBox()
        self.delay_min.setRange(0.5, 60.0)
        self.delay_min.setSingleStep(0.5)
        self.delay_min.setValue(3.0)
        self.delay_min.setToolTip("每页爬取最短间隔（秒）")
        delay_layout.addWidget(self.delay_min)
        delay_layout.addWidget(QLabel("~"))
        self.delay_max = QDoubleSpinBox()
        self.delay_max.setRange(0.5, 120.0)
        self.delay_max.setSingleStep(0.5)
        self.delay_max.setValue(6.0)
        self.delay_max.setToolTip("每页爬取最长间隔（秒），随机取值防封号")
        delay_layout.addWidget(self.delay_max)
        delay_layout.addWidget(QLabel("秒"))
        delay_widget = QWidget()
        delay_widget.setLayout(delay_layout)
        search_layout.addWidget(delay_widget, 2, 1, 1, 3)

        # 输出文件名
        search_layout.addWidget(QLabel("输出文件名:"), 2, 4)
        self.filename_input = QLineEdit()
        self.filename_input.setPlaceholderText("留空则使用搜索条件作为文件名")
        search_layout.addWidget(self.filename_input, 2, 5, 1, 1)
        
        self.auto_filename_cb = QComboBox()
        self.auto_filename_cb.addItems([".txt", ".csv"])
        search_layout.addWidget(self.auto_filename_cb, 2, 6)
        
        self.keyword_input.textChanged.connect(self._update_default_filename)
        
        search_group.setLayout(search_layout)
        layout.addWidget(search_group)
        
        # ===== 控制按钮区域 =====
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶ 开始爬取")
        self.start_btn.clicked.connect(self.start_spider)
        btn_layout.addWidget(self.start_btn)
        
        self.pause_btn = QPushButton("⏸ 暂停")
        self.pause_btn.clicked.connect(self.pause_spider)
        self.pause_btn.setEnabled(False)
        btn_layout.addWidget(self.pause_btn)
        
        self.stop_btn = QPushButton("⏹ 停止")
        self.stop_btn.clicked.connect(self.stop_spider)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)

        self.probe_btn = QPushButton("📡 探测存活")
        self.probe_btn.clicked.connect(self.start_probe)
        self.probe_btn.setEnabled(False)
        self.probe_btn.setToolTip("对扫描结果中的所有 Host 发起 HTTP 请求，检测是否可达")
        btn_layout.addWidget(self.probe_btn)

        self.stop_probe_btn = QPushButton("⏹ 停止探测")
        self.stop_probe_btn.clicked.connect(self.stop_probe)
        self.stop_probe_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_probe_btn)
        
        self.export_btn = QPushButton("💾 导出结果")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setEnabled(False)
        btn_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑 清空结果")
        self.clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(self.clear_btn)

        self.send_nuclei_btn = QPushButton("⚡ 发送到Nuclei")
        self.send_nuclei_btn.clicked.connect(self._send_all_to_nuclei)
        self.send_nuclei_btn.setEnabled(False)
        self.send_nuclei_btn.setToolTip("将所有爬取到的 Host 一键发送到 Nuclei 扫描模块")
        self.send_nuclei_btn.setStyleSheet(
            "QPushButton{border-color:#00aaff;color:#00aaff;}"
            "QPushButton:hover{background:#00aaff;color:#0a0a0a;}"
            "QPushButton:disabled{border-color:#333;color:#333;}"
        )
        btn_layout.addWidget(self.send_nuclei_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # ===== 进度区域 =====
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar, stretch=3)
        
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: #00ff41; font-weight: bold;")
        progress_layout.addWidget(self.status_label, stretch=1)
        
        layout.addLayout(progress_layout)
        
        # ===== 结果显示区域 =====
        result_group = QGroupBox("【 扫描结果  双击行查看详情 】")
        result_layout = QVBoxLayout()
        
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(
            ["Host", "IP", "Port", "协议", "标题", "状态"]
        )
        self.result_table.horizontalHeader().setStretchLastSection(False)
        self.result_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.result_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.result_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.result_table.setAlternatingRowColors(True)
        self.result_table.verticalHeader().setDefaultSectionSize(28)
        self.result_table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Fixed
        )
        self.result_table.cellDoubleClicked.connect(self._on_row_double_clicked)
        self.result_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.result_table.customContextMenuRequested.connect(
            self._table_context_menu
        )
        result_layout.addWidget(self.result_table)
        
        self.stats_label = QLabel("总计: 0 条结果")
        self.stats_label.setStyleSheet("color: #00aa33; font-size: 11px;")
        result_layout.addWidget(self.stats_label)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group, stretch=2)
        
        # ===== 日志区域 =====
        log_group = QGroupBox("【 系统日志 】")
        log_layout = QVBoxLayout()
        
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(1000)
        self.log_text.setPlaceholderText("系统日志将显示在这里...")
        log_layout.addWidget(self.log_text)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group, stretch=1)
        
    def apply_hacker_theme(self):
        """应用黑客主题"""
        self.setStyleSheet(HACKER_STYLESHEET)
        
    def _update_default_filename(self):
        """根据关键词更新默认文件名"""
        keyword = self.keyword_input.text().strip()
        if keyword and not self.filename_input.text().strip():
            safe_name = "".join(c if c.isalnum() or c in "_-" else "_" for c in keyword)
            self.filename_input.setPlaceholderText(f"{safe_name}{self.auto_filename_cb.currentText()}")
            
    def get_total_pages(self):
        """获取搜索结果的总页数"""
        keyword = self.keyword_input.text().strip()
        if not keyword:
            QMessageBox.warning(self, "警告", "请先输入搜索关键词")
            return
            
        cookie = self.config.get_cookie()
        if not cookie:
            QMessageBox.warning(self, "警告", "请先设置 Cookie")
            return
            
        self.get_pages_btn.setEnabled(False)
        self.get_pages_btn.setText("获取中...")
        self.status_label.setText("正在获取总页数...")
        
        self.pages_thread = GetPagesThread(cookie, keyword, self.config.get("fofa_authorization", ""))
        self.pages_thread.result_signal.connect(self._on_pages_result)
        self.pages_thread.start()
        
    def _on_pages_result(self, success: bool, total_pages: int, message: str):
        """获取页数结果回调"""
        self.get_pages_btn.setEnabled(True)
        self.get_pages_btn.setText("🔍 获取页数")
        
        if success:
            self.total_pages_label.setText(str(total_pages))
            self.end_page.setValue(total_pages)
            self.status_label.setText(f"该关键字共 {total_pages} 页")
            self.log(f"获取页数成功: 共 {total_pages} 页", "SUCCESS")
        else:
            self.status_label.setText("获取页数失败")
            self.log(f"获取页数失败: {message}", "ERROR")
            QMessageBox.warning(self, "获取失败", message)
        
    def log(self, message: str, msg_type: str = "INFO"):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "#00ff41",
            "WARN": "#ffaa00",
            "ERROR": "#ff0041",
            "SUCCESS": "#00ffff"
        }
        color = color_map.get(msg_type, "#00ff41")
        
        text = f"[{timestamp}] [{msg_type}] {message}"
        self.log_text.appendPlainText(text)
        
    def start_spider(self):
        """开始爬取"""
        keyword = self.keyword_input.text().strip()
        if not keyword:
            QMessageBox.warning(self, "警告", "请输入搜索关键词")
            return
            
        cookie = self.config.get_cookie()
        if not cookie:
            QMessageBox.warning(self, "警告", "请先设置 Fofa Cookie\n\n在设置菜单中配置 Cookie")
            return
            
        start = self.start_page.value()
        end = self.end_page.value()
        
        if start > end:
            QMessageBox.warning(self, "警告", "起始页不能大于结束页")
            return

        d_min = self.delay_min.value()
        d_max = self.delay_max.value()
        if d_min > d_max:
            d_min, d_max = d_max, d_min
            
        auth = self.config.get("fofa_authorization", "")
        self.spider = FofaSpider(
            cookie=cookie,
            authorization=auth,
            delay=(d_min, d_max)
        )
        self.spider.reset()
        
        self.spider_thread = SpiderThread(self.spider, keyword, start, end)
        self.spider_thread.progress_signal.connect(self.on_progress)
        self.spider_thread.result_signal.connect(self.on_result)
        self.spider_thread.finished_signal.connect(self.on_finished)
        
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.probe_btn.setEnabled(False)
        self.stop_probe_btn.setEnabled(False)
        
        self.progress_bar.setMaximum(end - start + 1)
        self.progress_bar.setValue(0)
        
        self.log(
            "开始爬取: %s, 页码: %d-%d, 间隔: %.1f~%.1f秒"
            % (keyword, start, end, d_min, d_max),
            "INFO"
        )
        
        self.spider_thread.start()
        
    def pause_spider(self):
        """暂停/继续爬取"""
        if not self.spider:
            return
            
        if self.pause_btn.text() == "⏸ 暂停":
            self.spider.pause()
            self.pause_btn.setText("▶ 继续")
            self.log("任务已暂停", "WARN")
        else:
            self.spider.resume()
            self.pause_btn.setText("⏸ 暂停")
            self.log("任务已继续", "INFO")
            
    def stop_spider(self):
        """停止爬取"""
        if self.spider:
            self.spider.stop()
            self.log("正在停止任务...", "WARN")
            
    def on_progress(self, current: int, total: int, message: str):
        """进度回调"""
        self.progress_bar.setValue(current)
        self.status_label.setText(message)
        self.log(message, "INFO")
        
    def on_result(self, results: list):
        """结果回调"""
        self.all_results.extend(results)
        self.update_table(results)
        self.stats_label.setText(f"总计: {len(self.all_results)} 条结果")
        
    def on_finished(self, success: bool, message: str):
        """完成回调"""
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.pause_btn.setText("⏸ 暂停")
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        if self.all_results:
            self.probe_btn.setEnabled(True)
            self.send_nuclei_btn.setEnabled(True)
        
        if success:
            self.log(message, "SUCCESS")
            self.status_label.setText("完成")
            self._auto_save()
        else:
            self.log(message, "ERROR")
            self.status_label.setText("失败")
            
    def _auto_save(self):
        """自动保存结果"""
        if not self.all_results:
            return
            
        custom_name = self.filename_input.text().strip()
        if custom_name:
            filename = custom_name
            if not filename.endswith(('.txt', '.csv')):
                filename += self.auto_filename_cb.currentText()
        else:
            keyword = self.keyword_input.text().strip()
            safe_name = "".join(c if c.isalnum() or c in "_-" else "_" for c in keyword)
            filename = f"{safe_name}{self.auto_filename_cb.currentText()}"
            
        filepath = Path("output") / filename
        filepath.parent.mkdir(exist_ok=True)
        
        format_type = "csv" if filename.endswith(".csv") else "txt"
        
        if save_results_to_file(self.all_results, str(filepath), format_type):
            self.log(f"结果已自动保存: {filepath}", "SUCCESS")
        else:
            self.log(f"自动保存失败: {filepath}", "ERROR")
            
    def update_table(self, results: list):
        """更新结果表格"""
        current_row = self.result_table.rowCount()
        self.result_table.setRowCount(current_row + len(results))
        
        for i, item in enumerate(results):
            row = current_row + i
            self.result_table.setItem(row, 0, QTableWidgetItem(item.get("host", "")))
            self.result_table.setItem(row, 1, QTableWidgetItem(item.get("ip", "")))
            self.result_table.setItem(row, 2, QTableWidgetItem(item.get("port", "")))
            self.result_table.setItem(row, 3, QTableWidgetItem(item.get("protocol", "")))
            self.result_table.setItem(row, 4, QTableWidgetItem(item.get("title", "")))
            status_item = QTableWidgetItem(item.get("status", "未探测"))
            status_item.setForeground(QColor("#555555"))
            self.result_table.setItem(row, 5, status_item)
            
    def export_results(self):
        """导出结果"""
        if not self.all_results:
            QMessageBox.information(self, "提示", "没有可导出的结果")
            return
            
        filepath, _ = QFileDialog.getSaveFileName(
            self, "保存结果", "output/fofa_results.txt",
            "文本文件 (*.txt);;CSV文件 (*.csv)"
        )
        
        if not filepath:
            return
            
        format_type = "csv" if filepath.endswith(".csv") else "txt"
        
        if save_results_to_file(self.all_results, filepath, format_type):
            QMessageBox.information(self, "成功", f"结果已保存到:\n{filepath}")
            self.log(f"手动导出成功: {filepath}", "SUCCESS")
        else:
            QMessageBox.critical(self, "错误", "保存文件失败")
            self.log("手动导出失败", "ERROR")
            
    def clear_results(self):
        """清空结果"""
        self.all_results.clear()
        self.result_table.setRowCount(0)
        self.stats_label.setText("总计: 0 条结果")
        self.progress_bar.setValue(0)
        self.status_label.setText("就绪")
        self.probe_btn.setEnabled(False)
        self.send_nuclei_btn.setEnabled(False)
        self.log("结果已清空", "INFO")

    def _on_row_double_clicked(self, row: int, _col: int):
        """双击结果行弹出详情对话框"""
        if row >= len(self.all_results):
            row_data = {
                "host":     self._table_text(row, 0),
                "ip":       self._table_text(row, 1),
                "port":     self._table_text(row, 2),
                "protocol": self._table_text(row, 3),
                "title":    self._table_text(row, 4),
                "status":   self._table_text(row, 5),
            }
        else:
            row_data = dict(self.all_results[row])
            row_data.setdefault("status", self._table_text(row, 5))
        dlg = ResultDetailDialog(row_data, self)
        dlg.exec()

    def _table_text(self, row: int, col: int) -> str:
        item = self.result_table.item(row, col)
        return item.text() if item else ""

    def start_probe(self):
        """开始存活探测（手动触发）"""
        if not self.all_results:
            QMessageBox.information(self, "提示", "没有可探测的结果，请先爬取数据")
            return

        hosts = []
        for row, item in enumerate(self.all_results):
            url = item.get("host", "").strip()
            if url:
                hosts.append((row, url))

        if not hosts:
            QMessageBox.information(self, "提示", "结果中没有有效的 Host URL")
            return

        reply = QMessageBox.question(
            self, "确认探测",
            "将对 %d 个 Host 发起 HTTP 请求探测存活状态。\n"
            "探测过程可能较慢，是否继续？" % len(hosts),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        for row in range(self.result_table.rowCount()):
            pending_item = QTableWidgetItem("⏳ 等待中")
            pending_item.setForeground(QColor("#555555"))
            self.result_table.setItem(row, 5, pending_item)

        self.probe_btn.setEnabled(False)
        self.stop_probe_btn.setEnabled(True)
        self.status_label.setText("探测中...")
        self.log("开始存活探测，共 %d 个 Host" % len(hosts), "INFO")

        self._probe_alive = 0
        self._probe_total = len(hosts)

        self.probe_thread = ProbeThread(hosts, timeout=5.0)
        self.probe_thread.probe_result_signal.connect(self._on_probe_result)
        self.probe_thread.probe_finished_signal.connect(self._on_probe_finished)
        self.probe_thread.start()

    def stop_probe(self):
        """停止探测"""
        if self.probe_thread and self.probe_thread.isRunning():
            self.probe_thread.stop()
            self.log("探测已手动停止", "WARN")
        self.stop_probe_btn.setEnabled(False)
        self.probe_btn.setEnabled(True)

    def _on_probe_result(self, row: int, status: str, color: str):
        """单个探测结果回调"""
        item = QTableWidgetItem(status)
        item.setForeground(QColor(color))
        self.result_table.setItem(row, 5, item)

        if row < len(self.all_results):
            self.all_results[row]["status"] = status

        done = sum(
            1 for r in range(self.result_table.rowCount())
            if self._table_text(r, 5) not in ("未探测", "⏳ 等待中", "")
        )
        self.status_label.setText(
            "探测中 %d / %d" % (done, self._probe_total)
        )

    def _on_probe_finished(self, alive: int, total: int):
        """全部探测完成"""
        self.probe_btn.setEnabled(True)
        self.stop_probe_btn.setEnabled(False)
        msg = "探测完成：%d / %d 存活" % (alive, total)
        self.status_label.setText(msg)
        self.log(msg, "SUCCESS")

    def _send_all_to_nuclei(self):
        """一键发送所有爬取结果到 Nuclei 扫描模块"""
        if not self.all_results:
            QMessageBox.information(self, "提示", "没有可发送的结果")
            return
        hosts = [item.get("host", "").strip() for item in self.all_results
                 if item.get("host", "").strip()]
        if not hosts:
            QMessageBox.information(self, "提示", "结果中没有有效的 Host URL")
            return
        reply = QMessageBox.question(
            self, "发送到 Nuclei",
            "将把 %d 个 Host 发送到 Nuclei 扫描模块，是否继续？" % len(hosts),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.send_to_nuclei.emit(hosts)
            self.log("已发送 %d 个 Host 到 Nuclei 模块" % len(hosts), "SUCCESS")

    def _table_context_menu(self, pos):
        """表格右键菜单"""
        row = self.result_table.rowAt(pos.y())
        if row < 0:
            return

        host = self._table_text(row, 0)
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#0a0a0a;border:1px solid #00ff41;color:#00ff41;}"
            "QMenu::item{padding:5px 20px;}"
            "QMenu::item:selected{background:#00ff41;color:#0a0a0a;}"
        )

        detail_act   = menu.addAction("🔍 查看详情")
        copy_act     = menu.addAction("📋 复制 Host")
        probe_act    = menu.addAction("📡 探测该 Host 存活")
        menu.addSeparator()
        nuclei_act   = menu.addAction("⚡ 发送到 Nuclei 扫描")
        menu.addSeparator()
        del_act      = menu.addAction("🗑 删除该行")

        action = menu.exec(self.result_table.viewport().mapToGlobal(pos))

        if action == detail_act:
            self._on_row_double_clicked(row, 0)

        elif action == copy_act:
            QApplication.clipboard().setText(host)

        elif action == probe_act:
            if not host:
                return
            self.probe_btn.setEnabled(False)
            self.stop_probe_btn.setEnabled(True)
            self.status_label.setText("探测中...")
            pending = QTableWidgetItem("⏳ 等待中")
            pending.setForeground(QColor("#555555"))
            self.result_table.setItem(row, 5, pending)
            self._probe_total = 1
            self.probe_thread = ProbeThread([(row, host)], timeout=5.0)
            self.probe_thread.probe_result_signal.connect(self._on_probe_result)
            self.probe_thread.probe_finished_signal.connect(self._on_probe_finished)
            self.probe_thread.start()

        elif action == nuclei_act:
            if host:
                self.send_to_nuclei.emit([host])
                self.log("已发送 [%s] 到 Nuclei 模块" % host, "SUCCESS")

        elif action == del_act:
            self.result_table.removeRow(row)
            if row < len(self.all_results):
                self.all_results.pop(row)
            self.stats_label.setText("总计: %d 条结果" % len(self.all_results))
